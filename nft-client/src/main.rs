//! This is an example of an off-chain application which integrates with a smart
//! contract on chain. The application is a client for working with a specific
//! implementation of a Non-fungible token(NFT) smart contract.
//! The smart contract should follow the CTS1 specification, but some additional
//! assumptions are made for how the contract serializes the state and the
//! existence of a "mint" contract function.
//!
//! The smart contract is called "CTS1-NFT" and can be found [here](https://github.com/Concordium/concordium-rust-smart-contracts/tree/main/examples).
//!
//! Most of the functionality needs access to the GRPC API of a running
//! concordium-node. Some functionality of the client additionally depends on
//! the concordium-node to have the transaction logging enabled and access to
//! the PostgreSQL database with transaction logs.

use anyhow::*;
use clap::AppSettings;
use common::{SerdeDeserialize, SerdeSerialize};
use concordium_rust_sdk::{
    common, constants,
    endpoints::{Client, Endpoint},
    id, postgres,
    postgres::DatabaseSummaryEntry,
    types,
};
use futures::{StreamExt, TryStreamExt};
use smart_contracts::concordium_contracts_common;
use std::{
    collections::{BTreeMap as Map, BTreeSet as Set},
    convert::{TryFrom, TryInto},
    fmt::Display,
    path::PathBuf,
    str::FromStr,
};
use structopt::*;
use thiserror::*;
use types::{smart_contracts, transactions};

mod cts1;
use concordium_contracts_common::Deserial;

/// Name of the NFT smart contract from the example implementing the CTS1
/// specification.
const NFT_CONTRACT_NAME: &str = "CTS1-NFT";

/// The NFT contract state for each address.
/// Important: this structure matches the NFT contract implementations and
/// cannot be assumed for any CTS1 contract state, as the CTS1 does not restrict
/// the state in anyway.
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct NFTContractAddressState {
    /// The tokens owned by this address.
    owned_tokens: Set<cts1::TokenIdVec>,
    /// The address which are currently enabled as operators for this address.
    operators:    Set<concordium_contracts_common::Address>,
}

/// Deserialization of AddressState.
/// Important: this deserialization matches the NFT contract implementations
/// and cannot be assumed for any CTS1 contract state is serialized, as the CTS1
/// does not restrict how to encode the state in anyway.
impl Deserial for NFTContractAddressState {
    fn deserial<R: concordium_contracts_common::Read>(
        source: &mut R,
    ) -> Result<Self, concordium_contracts_common::ParseError> {
        let owned_tokens_length = u16::deserial(source)?;
        let owned_tokens = concordium_contracts_common::deserial_set_no_length_no_order_check(
            source,
            owned_tokens_length.into(),
        )?;
        let operators_length = u8::deserial(source)?;
        let operators =
            concordium_contracts_common::deserial_set_no_length(source, operators_length.into())?;
        Ok(NFTContractAddressState {
            owned_tokens,
            operators,
        })
    }
}

/// The NFT contract state.
/// Important: this structure matches the NFT contract implementations and
/// cannot be assumed for any CTS1 contract state, as the CTS1 does not restrict
/// the state in anyway.
#[derive(Debug)]
struct NFTContractState {
    state: Map<concordium_contracts_common::Address, NFTContractAddressState>,
}

/// Deserialization of the NFT contract state.
/// Important: this deserialization matches the NFT contract implementations
/// and cannot be assumed for any CTS1 contract state is serialized, as the CTS1
/// does not restrict how to encode the state in anyway.
impl concordium_contracts_common::Deserial for NFTContractState {
    fn deserial<R: concordium_contracts_common::Read>(
        source: &mut R,
    ) -> Result<Self, concordium_contracts_common::ParseError> {
        let length = u32::deserial(source)?;
        let state =
            concordium_contracts_common::deserial_map_no_length(source, length.try_into()?)?;
        Ok(NFTContractState { state })
    }
}

/// Wrapper for contract address to implement FromStr and Display using the
/// "<54,0>" notation for contract address with index 54 and subindex 0.
#[derive(Debug)]
struct ContractAddressWrapper(types::ContractAddress);

/// Error from parsing Contract address from a string.
#[derive(Debug, Error)]
enum ParseContractAddressError {
    #[error("Failed to parse the index/subindex integer: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Missing comma separater between index and subindex")]
    NoCommaError,
}

/// Parse a ContractAddressWrapper from a string of "<index,subindex>" where
/// index and subindex are replaced with an u64.
impl FromStr for ContractAddressWrapper {
    type Err = ParseContractAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = &s[1..s.len() - 1];
        let (index, sub_index) = trimmed
            .split_once(",")
            .ok_or(ParseContractAddressError::NoCommaError)?;
        let index = u64::from_str(index)?;
        let sub_index = u64::from_str(sub_index)?;
        Ok(ContractAddressWrapper(types::ContractAddress::new(
            types::ContractIndex { index },
            types::ContractSubIndex { sub_index },
        )))
    }
}

/// Display a contract address using the <index,subindex> notation where index
/// and subindex are replaced with an u64.
impl Display for ContractAddressWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "<{},{}>", self.0.index.index, self.0.subindex.sub_index)
    }
}

/// Name of a contract receive function, wrapped to implement FromStr.
#[derive(Debug, Clone)]
pub struct OwnedReceiveNameWrapper(concordium_contracts_common::OwnedReceiveName);

/// Parses a contract receive function name.
impl FromStr for OwnedReceiveNameWrapper {
    type Err = concordium_contracts_common::NewReceiveNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(OwnedReceiveNameWrapper(
            concordium_contracts_common::OwnedReceiveName::new(s.to_string())?,
        ))
    }
}

/// Wrapper for Address to implement FromStr and Display using for strings which
/// are either an account address or contract address.
#[derive(Debug)]
struct AddressWrapper(types::Address);

/// Parse a string into an address, by first trying to parse the string as a
/// contract address string, otherwise try parsing as an account address string.
impl FromStr for AddressWrapper {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let contract_result = ContractAddressWrapper::from_str(s);
        let address = if let Ok(contract) = contract_result {
            types::Address::Contract(contract.0)
        } else {
            types::Address::Account(id::types::AccountAddress::from_str(s)?)
        };
        Ok(AddressWrapper(address))
    }
}

/// Display the Address using contract notation <index,subindex> for contract
/// addresses and display for account addresses.
impl Display for AddressWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self.0 {
            types::Address::Account(a) => a.fmt(f),
            types::Address::Contract(c) => ContractAddressWrapper(c).fmt(f),
        }
    }
}

/// Helper to parse account keys JSON format.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct AccountData {
    /// The keys for the account address.
    account_keys: id::types::AccountKeys,
    /// The account address.
    address:      id::types::AccountAddress,
}

fn box_postgres_from_str(s: &str) -> Result<Box<postgres::Config>, tokio_postgres::Error> {
    Ok(Box::new(s.parse()?))
}

/// Structure to hold command-line arguments.
#[derive(StructOpt)]
#[structopt(
    bin_name = "nft-client",
    about = "NFT client tool for interacting with CTS1 NFT token contracts on the Concordium \
             blockchain"
)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: Endpoint,
    #[structopt(subcommand)]
    command:  Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(
        name = "show",
        help = "Prints all addresses owning tokens and a list of the token IDs they currently own."
    )]
    PrintState {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract: ContractAddressWrapper,
    },
    #[structopt(
        name = "trace-events",
        help = "Follow and print events for the contract."
    )]
    Trace {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract: ContractAddressWrapper,
        #[structopt(
            long = "db",
            default_value = "host=localhost dbname=nft_client_logging user=nft-client \
                             password=arstneio port=5432",
            help = "Database connection string.",
            parse(try_from_str = box_postgres_from_str)
        )]
        config:   Box<postgres::Config>,
    },
    #[structopt(
        name = "mint",
        help = "Send mint transaction to NFT contract, with the given token IDs."
    )]
    Mint {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract:  ContractAddressWrapper,
        #[structopt(
            name = "sender",
            long = "sender",
            help = "JSON file containing the account keys."
        )]
        sender:    PathBuf,
        #[structopt(help = "Token ID to mint in the contract.")]
        token_ids: Vec<cts1::TokenIdVec>,
    },
    #[structopt(name = "transfer", help = "Transfer one NFT to another address.")]
    Transfer {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract:     ContractAddressWrapper,
        #[structopt(
            name = "sender",
            long = "sender",
            help = "JSON file containing the account keys."
        )]
        sender:       PathBuf,
        #[structopt(
            name = "token_id",
            long = "token",
            help = "Token ID to transfer in the contract."
        )]
        token_ids:    Vec<cts1::TokenIdVec>,
        #[structopt(
            name = "from",
            long = "from",
            help = "The current owner of the token being transferred.
                    This is either an account address or a contract address. Note that contract \
                    addresses are written using the notation <index, subindex> where the index \
                    and subindex are replaced with integers."
        )]
        from:         AddressWrapper,
        #[structopt(
            name = "to",
            long = "to",
            help = "The address to receive the token being transferred.
                    This is either an account address or a contract address. Note that contract \
                    addresses are written using the notation <index, subindex> where the index \
                    and subindex are replaced with integers."
        )]
        to:           AddressWrapper,
        #[structopt(
            name = "to-func",
            long = "to-func",
            help = "The receive function name to call on the contract receiving tokens, only used \
                    when `--to` is a contract address."
        )]
        to_func:      Option<OwnedReceiveNameWrapper>,
        #[structopt(
            name = "to-func-data",
            long = "to-func-data",
            help = "Some bytes (hex encoded) to include when calling receive function on the \
                    contract receiving tokens, only used when `--to` is a contract address.",
            default_value = ""
        )]
        to_func_data: cts1::ReceiveHookData,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap()
            .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    match app.command {
        Command::PrintState { contract } => {
            // The GRPC client for Concordium node.
            let mut grpc_client = Client::connect(app.endpoint, "rpcadmin".to_string())
                .await
                .context("Failed to connect to Node GRPC")?;

            let consensus_status = grpc_client.get_consensus_status().await?;
            let instance_info = grpc_client
                .get_instance_info(contract.0, &consensus_status.best_block)
                .await?;
            let mut cursor = concordium_contracts_common::Cursor::new(instance_info.model);
            let state = NFTContractState::deserial(&mut cursor)
                .map_err(|_| anyhow!("Failed parsing contract state"))?;
            pretty_print_contract_state(&state);
        }
        Command::Trace { contract, config } => {
            eprintln!("Connecting to PostgreSQL");
            let (db_client, mut connection) = config.connect(postgres::NoTls).await?;

            // Poll PostgreSQL notifications
            let mut notifications = {
                let stream = futures::stream::poll_fn(move |ctx| connection.poll_message(ctx))
                    .map_err(|e| panic!("{}", e));

                let notification_stream = stream.filter_map(|message| async {
                    if let Ok(tokio_postgres::AsyncMessage::Notification(n)) = message {
                        Some(Ok(n))
                    } else {
                        None
                    }
                });

                let (tx, rx) = futures::channel::mpsc::unbounded();
                tokio::spawn(notification_stream.forward(tx));
                rx
            };

            // Setup a PostgreSQL trigger on insert in the contract index table and notify
            // for insertions relevant for our contract.
            eprintln!("Setting up PostgreSQL trigger and notifications.");
            db_client
                .execute(
                    format!(
                        "CREATE FUNCTION pg_temp.notify_insert () RETURNS TRIGGER AS $psql$
                        BEGIN
                            IF NEW.index = {} AND NEW.subindex = {} THEN
                                PERFORM pg_notify('contract_updates', NEW.summary::text);
                            END IF;
                            RETURN NEW;
                        END;$psql$ LANGUAGE plpgsql",
                        contract.0.index.index, contract.0.subindex.sub_index
                    )
                    .as_str(),
                    &[],
                )
                .await
                .context("Failed creating PostgreSQL 'notify_insert' function")?;

            db_client
                .batch_execute(
                    "CREATE TRIGGER notify_on_insert_into_cti AFTER INSERT ON cti FOR EACH ROW \
                     EXECUTE PROCEDURE pg_temp.notify_insert();
                         LISTEN contract_updates;",
                )
                .await
                .context("Failed creating PostgreSQL trigger")?;

            // Await notifications, find and parse the relevant transaction summaries
            eprintln!("Started tracing contract events:");
            while let Some(notification) = notifications.next().await {
                if notification.channel() != "contract_updates" {
                    continue;
                }
                let summary_index: i64 = notification.payload().parse()?;

                let row = db_client
                    .query_one("SELECT summary FROM summaries WHERE id = $1", &[
                        &summary_index,
                    ])
                    .await?;
                let summary = serde_json::from_value::<DatabaseSummaryEntry>(row.get(0))?;
                let events = collect_summary_contract_events(summary, contract.0);
                for event in events {
                    let mut cursor = concordium_contracts_common::Cursor::new(event.as_ref());
                    let event = cts1::Event::deserial(&mut cursor)
                        .map_err(|_| anyhow!("Failed parsing event"))?;
                    println!("{}", event);
                }
            }
        }
        Command::Mint {
            sender,
            token_ids,
            contract,
        } => {
            let account_data: AccountData = serde_json::from_str(
                &std::fs::read_to_string(sender).context("Could not read the keys file.")?,
            )
            .context("Could not parse the accounts file.")?;

            let owner = convert_account_address(&account_data.address);
            let mint_parameter = cts1::MintParams {
                owner:     concordium_contracts_common::Address::Account(owner),
                token_ids: token_ids.clone(),
            };
            let bytes = concordium_contracts_common::to_bytes(&mint_parameter);

            let update_payload = transactions::UpdateContractPayload {
                amount:       common::types::Amount::from(0),
                address:      contract.0,
                receive_name: smart_contracts::ReceiveName::try_from(format!(
                    "{}.mint",
                    NFT_CONTRACT_NAME
                ))
                .map_err(|e| anyhow!("Failed to parse receive name {}", e))?,
                message:      smart_contracts::Parameter::from(bytes),
            };

            let transaction_payload = transactions::Payload::Update {
                payload: update_payload,
            };
            eprint!("Minting tokens with id: ");
            for token_id in token_ids {
                eprint!("{} ", token_id);
            }
            eprintln!();

            // The GRPC client for Concordium node.
            let mut grpc_client = Client::connect(app.endpoint, "rpcadmin".to_string())
                .await
                .context("Failed to connect to Node GRPC")?;

            let hash =
                send_transaction(&mut grpc_client, &account_data, transaction_payload).await?;
            eprintln!("Transaction with hash {} sent", hash);
        }
        Command::Transfer {
            sender,
            token_ids,
            from,
            to,
            to_func,
            to_func_data,
            contract,
        } => {
            let account_data: AccountData = serde_json::from_str(
                &std::fs::read_to_string(sender).context("Could not read the keys file.")?,
            )
            .context("Could not parse the accounts file.")?;

            let transfers = token_ids
                .iter()
                .map(|token_id| cts1::Transfer {
                    token_id:     token_id.clone(),
                    amount:       1,
                    from:         convert_address(from.0.clone()),
                    to:           convert_address(to.0.clone()),
                    receive_name: to_func.as_ref().map(|wrapper| wrapper.clone().0),
                    data:         to_func_data.clone(),
                })
                .collect();

            let parameter = cts1::TransferParams(transfers);
            let bytes = concordium_contracts_common::to_bytes(&parameter);

            let payload = transactions::UpdateContractPayload {
                amount:       common::types::Amount::from(0),
                address:      contract.0,
                receive_name: smart_contracts::ReceiveName::try_from(format!(
                    "{}.transfer",
                    NFT_CONTRACT_NAME
                ))
                .map_err(|e| anyhow!("Failed to parse receive name {}", e))?,
                message:      smart_contracts::Parameter::from(bytes),
            };

            let transaction_payload = transactions::Payload::Update { payload };
            eprintln!(
                "Transferring tokens {:?} from {} to {:?}",
                token_ids, from, to
            );
            // The GRPC client for Concordium node.
            let mut grpc_client = Client::connect(app.endpoint, "rpcadmin".to_string())
                .await
                .context("Failed to connect to Node GRPC")?;

            let hash =
                send_transaction(&mut grpc_client, &account_data, transaction_payload).await?;
            eprintln!("Transaction with hash {} sent", hash);
        }
    }

    Ok(())
}

/// Collect every contract event in a transaction summary for a given contract
/// address.
fn collect_summary_contract_events(
    entry: DatabaseSummaryEntry,
    contract: types::ContractAddress,
) -> Vec<smart_contracts::ContractEvent> {
    let effects = if let DatabaseSummaryEntry::BlockItem(types::BlockItemSummary {
        details: types::BlockItemSummaryDetails::AccountTransaction(tx),
        ..
    }) = entry
    {
        tx.effects
    } else {
        return Vec::new();
    };

    match effects {
        types::AccountTransactionEffects::ContractInitialized { data }
            if data.address == contract =>
        {
            data.events
        }
        types::AccountTransactionEffects::ContractUpdateIssued { effects } => {
            let mut events = Vec::new();
            for effect in effects {
                if let types::ContractTraceElement::Updated { data } = effect {
                    if data.address == contract {
                        events.extend(data.events)
                    }
                }
            }
            events
        }
        _ => Vec::new(),
    }
}

/// Convert an account address from `types` to an account address from
/// `concordium_contracts_common`.
fn convert_account_address(
    account: &id::types::AccountAddress,
) -> concordium_contracts_common::AccountAddress {
    let mut address_bytes = [0u8; 32];
    address_bytes.copy_from_slice(account.as_ref());
    concordium_contracts_common::AccountAddress(address_bytes)
}

/// Convert a contract address from `types` to a contract address from
/// `concordium_contracts_common`.
fn convert_contract_address(
    contract: &types::ContractAddress,
) -> concordium_contracts_common::ContractAddress {
    concordium_contracts_common::ContractAddress {
        index:    contract.index.index,
        subindex: contract.subindex.sub_index,
    }
}

/// Convert an address from `types` to an address from
/// `concordium_contracts_common`.
fn convert_address(address: types::Address) -> concordium_contracts_common::Address {
    match address {
        types::Address::Account(addr) => {
            concordium_contracts_common::Address::Account(convert_account_address(&addr))
        }
        types::Address::Contract(addr) => {
            concordium_contracts_common::Address::Contract(convert_contract_address(&addr))
        }
    }
}

/// Print the NFT contract state in a human readable format.
fn pretty_print_contract_state(state: &NFTContractState) {
    for (owner, address_state) in &state.state {
        match owner {
            concordium_contracts_common::Address::Account(addr) => println!("\n\n{}", addr),
            concordium_contracts_common::Address::Contract(addr) => println!("\n\n{}", addr),
        }
        if !address_state.owned_tokens.is_empty() {
            println!("  Owned Token IDs");
            for token in &address_state.owned_tokens {
                println!("    - {}", token);
            }
        }
        if !address_state.operators.is_empty() {
            println!("  Operators");
            for operator in &address_state.operators {
                println!("    - {:?}", operator);
            }
        }
    }
}

/// Build and send a transaction from a payload
async fn send_transaction(
    client: &mut Client,
    account_data: &AccountData,
    payload: transactions::Payload,
) -> anyhow::Result<types::hashes::TransactionHash> {
    let next_account_nonce = client.get_next_account_nonce(&account_data.address).await?;
    let expiry =
        common::types::TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let energy = transactions::send::GivenEnergy::Add(3000.into());
    let tx = transactions::send::make_and_sign_transaction(
        &account_data.account_keys,
        account_data.address,
        next_account_nonce.nonce,
        expiry,
        energy,
        &payload,
    );
    let bi = transactions::BlockItem::AccountTransaction(tx);
    let hash = bi.hash();
    if client
        .send_transaction(constants::DEFAULT_NETWORK_ID, &bi)
        .await?
    {
        Ok(hash)
    } else {
        bail!("Transaction was rejected by the node.")
    }
}
