//! This is an example of an off-chain application which integrates with a smart
//! contract on chain. The application is a client for working with a specific
//! implementation of a Non-fungible token(NFT) smart contract.
//! The smart contract should follow the CIS1 specification, but some additional
//! assumptions are made for how the contract serializes the state and the
//! existence of a "mint" contract function.
//!
//! The smart contract is called "CIS1-NFT" and can be found [here](https://github.com/Concordium/concordium-rust-smart-contracts/tree/main/examples).
//!
//! Most of the functionality needs access to the GRPC API of a running
//! concordium-node. Some functionality of the client additionally depends on
//! the concordium-node to have the transaction logging enabled and access to
//! the PostgreSQL database with transaction logs.

use anyhow::*;
use clap::AppSettings;
use common::{SerdeDeserialize, SerdeSerialize};
use concordium_contracts_common::{Deserial, Serial};
use concordium_rust_sdk::{
    cis2, common,
    endpoints::{Client, Endpoint},
    id, postgres,
    postgres::DatabaseSummaryEntry,
    types::{
        self,
        smart_contracts::{OwnedContractName, OwnedReceiveName},
    },
};
use futures::{StreamExt, TryStreamExt};
use smart_contracts::concordium_contracts_common::{
    self, AccountAddress, Address, Amount, ContractAddress,
};
use std::{
    collections::{BTreeMap as Map, BTreeSet as Set},
    path::PathBuf,
};
use structopt::*;

use types::{smart_contracts, transactions};

/// Name of the NFT smart contract from the example implementing the CIS2
/// specification.
const NFT_CONTRACT_NAME: &str = "CIS2-NFT";

/// The NFT contract state for each address.
/// Important: this structure matches the NFT contract implementations and
/// cannot be assumed to work for all CIS2 contract states, as the CIS2 does not
/// restrict the state in anyway.
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserial)]
struct NFTContractAddressState {
    /// The tokens owned by this address.
    owned_tokens: Set<cis2::TokenId>,
    /// The addresses which are currently enabled as operators for this address.
    operators:    Set<Address>,
}

/// The NFT contract state returned by the view function `view`, which is not
/// part of CIS2 and is only implemented for debugging purposes.
///
/// Important: this structure matches the NFT contract implementations and
/// cannot be assumed to work for all CIS2 contract states, as the CIS2 does not
/// restrict the state in anyway.
#[derive(Debug, Deserial)]
struct NFTContractState {
    state: Map<Address, NFTContractAddressState>,
}

/// Helper to parse account keys JSON format.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct AccountData {
    /// The keys for the account address.
    account_keys: id::types::AccountKeys,
    /// The account address.
    address:      AccountAddress,
}

/// The parameter for the NFT Contract function "CIS2-NFT.mint".
/// Important: this is specific to this NFT smart contract and contract
/// functions for minting are not part of the CIS2 specification.
#[derive(Debug, Serial)]
struct MintParams {
    owner:     Address,
    #[concordium(size_length = 1)]
    token_ids: Vec<cis2::TokenId>,
}

impl MintParams {
    fn new(owner: Address, token_ids: Vec<cis2::TokenId>) -> anyhow::Result<Self> {
        ensure!(
            token_ids.len() > 255,
            "The parameter for minting NFTs only support up to 255 at a time."
        );
        Ok(MintParams { owner, token_ids })
    }
}

fn box_postgres_from_str(s: &str) -> Result<Box<postgres::Config>, tokio_postgres::Error> {
    Ok(Box::new(s.parse()?))
}

/// Structure to hold command-line arguments.
#[derive(StructOpt)]
#[structopt(
    bin_name = "nft-client",
    about = "NFT client tool for interacting with CIS2 NFT token contracts on the Concordium \
             blockchain"
)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:   Endpoint,
    #[structopt(
        long = "rpc-auth-token",
        help = "GRPC authentication token.",
        default_value = "rpcadmin"
    )]
    auth_token: String,
    #[structopt(subcommand)]
    command:    Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(
        name = "show",
        help = "Prints all addresses owning tokens and a list of the token IDs they currently own."
    )]
    PrintState {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract: ContractAddress,
    },
    #[structopt(
        name = "balanceOf",
        help = "Query the balance of an address for some token ID."
    )]
    QueryBalanceOf {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract:  ContractAddress,
        #[structopt(long = "token", help = "Token ID to mint in the contract.")]
        token_id:  cis2::TokenId,
        #[structopt(
            long = "address",
            help = "The addresses to query the balance of.
                    This is either an account address or a contract address. Note that contract \
                    addresses are written using the notation <index, subindex> where the index \
                    and subindex are replaced with integers."
        )]
        addresses: Vec<Address>,
    },
    #[structopt(
        name = "trace-events",
        help = "Follow and print events for the contract."
    )]
    Trace {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract: ContractAddress,
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
        #[structopt(long = "contract", help = "NFT contract address.")]
        contract:  ContractAddress,
        #[structopt(
            long = "energy",
            help = "Maximum allowed amount of energy to spend on the transaction.",
            default_value = "10000"
        )]
        energy:    u64,
        #[structopt(
            name = "sender",
            long = "sender",
            help = "JSON file containing the account keys."
        )]
        sender:    PathBuf,
        #[structopt(help = "Token ID to mint in the contract.")]
        token_ids: Vec<cis2::TokenId>,
    },
    #[structopt(name = "transfer", help = "Transfer one NFT to another address.")]
    Transfer {
        #[structopt(long = "contract", help = "NFT contract address")]
        contract:     ContractAddress,
        #[structopt(
            name = "sender",
            long = "sender",
            help = "JSON file containing the account keys."
        )]
        sender:       PathBuf,
        #[structopt(
            long = "energy",
            help = "Maximum allowed amount of energy to spend on the transaction.",
            default_value = "10000"
        )]
        energy:       u64,
        #[structopt(
            name = "token_id",
            long = "token",
            help = "Token ID to transfer in the contract."
        )]
        token_ids:    Vec<cis2::TokenId>,
        #[structopt(
            name = "from",
            long = "from",
            help = "The current owner of the token being transferred.
                    This is either an account address or a contract address. Note that contract \
                    addresses are written using the notation <index, subindex> where the index \
                    and subindex are replaced with integers."
        )]
        from:         Address,
        #[structopt(
            name = "to",
            long = "to",
            help = "The address to receive the token being transferred.
                    This is either an account address or a contract address. Note that contract \
                    addresses are written using the notation <index, subindex> where the index \
                    and subindex are replaced with integers."
        )]
        to:           Address,
        #[structopt(
            name = "to-func",
            long = "to-func",
            help = "The receive function name to call on the contract receiving tokens, only used \
                    when `--to` is a contract address."
        )]
        to_func:      Option<OwnedReceiveName>,
        #[structopt(
            name = "to-func-data",
            long = "to-func-data",
            help = "Some bytes (hex encoded) to include when calling receive function on the \
                    contract receiving tokens, only used when `--to` is a contract address.",
            default_value = ""
        )]
        to_func_data: cis2::AdditionalData,
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
            let mut grpc_client = Client::connect(app.endpoint, app.auth_token)
                .await
                .context("Failed to connect to Node GRPC")?;

            let consensus_status = grpc_client
                .get_consensus_status()
                .await
                .context("Failed to get the consensus status")?;
            let contract_context = smart_contracts::ContractContext::new(
                contract,
                format!("{}.view", NFT_CONTRACT_NAME)
                    .parse()
                    .context("Failed to construct receive name")?,
            );
            let invoke_result = grpc_client
                .invoke_contract(&consensus_status.last_finalized_block, &contract_context)
                .await
                .context("Failed to invoke contract")?;
            let model = match invoke_result {
                smart_contracts::InvokeContractResult::Success { return_value, .. } => {
                    if let Some(value) = return_value {
                        value.value
                    } else {
                        bail!("Invoking the smart contract failed to provide a return value");
                    }
                }
                smart_contracts::InvokeContractResult::Failure { reason, .. } => {
                    bail!(
                        "Invoking the smart contract resulted in a failure: {:?}",
                        reason
                    );
                }
            };
            let state: NFTContractState = concordium_contracts_common::from_bytes(&model)
                .context("Failed parsing contract state")?;
            pretty_print_contract_state(&state);
        }
        Command::QueryBalanceOf {
            contract,
            token_id,
            addresses,
        } => {
            let mut grpc_client = Client::connect(app.endpoint, app.auth_token)
                .await
                .context("Failed to connect to Node GRPC")?;
            let cis2_contract_name = OwnedContractName::new_unchecked("init_CIS2-NFT".to_string());
            let mut cis2_contract =
                cis2::Cis2Contract::new(grpc_client.clone(), contract, cis2_contract_name);

            let queries: Vec<cis2::BalanceOfQuery> = addresses
                .iter()
                .map(|&address| cis2::BalanceOfQuery {
                    address,
                    token_id: token_id.clone(),
                })
                .collect();
            let consensus_status = grpc_client.get_consensus_status().await?;

            let result = cis2_contract
                .balance_of(&consensus_status.last_finalized_block, queries.clone())
                .await
                .context("Failed invoking the query")?;

            eprintln!("Balances for token {}", token_id);
            for (address, balance) in addresses.iter().zip(result.as_ref().iter()) {
                eprintln!("- {} : {}", address, balance);
            }
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
                        contract.index, contract.subindex
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
                let events = collect_summary_contract_events(summary, contract);
                for event in events {
                    let event: cis2::Event =
                        concordium_contracts_common::from_bytes(event.as_ref())
                            .context("Failed parsing event")?;
                    println!("{}", event);
                }
            }
        }
        Command::Mint {
            sender,
            token_ids,
            contract,
            energy,
        } => {
            let account_data: AccountData = serde_json::from_str(
                &std::fs::read_to_string(sender).context("Could not read the keys file.")?,
            )
            .context("Could not parse the accounts file.")?;

            let mint_parameter = MintParams::new(account_data.address.into(), token_ids.clone())
                .context("Failed to construct mint parameter")?;
            let bytes = concordium_contracts_common::to_bytes(&mint_parameter);

            let update_payload = transactions::UpdateContractPayload {
                amount:       common::types::Amount::zero(),
                address:      contract,
                receive_name: format!("{}.mint", NFT_CONTRACT_NAME)
                    .parse()
                    .context("Failed to parse receive name")?,
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
            let mut grpc_client = Client::connect(app.endpoint, app.auth_token)
                .await
                .context("Failed to connect to Node GRPC")?;

            let hash = send_transaction(
                &mut grpc_client,
                &account_data,
                transaction_payload,
                transactions::send::GivenEnergy::Add(energy.into()),
            )
            .await?;
            eprintln!("Transaction with hash {} sent", hash);
        }
        Command::Transfer {
            sender,
            energy,
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

            let to = match to {
                Address::Account(address) => cis2::Receiver::Account(address),
                Address::Contract(address) => {
                    let receive_name = to_func.context(
                        "Transferring to a contract, requires inputting a receive function \
                         --to-func",
                    )?;
                    cis2::Receiver::Contract(address, receive_name)
                }
            };

            let transfers = token_ids
                .iter()
                .map(|token_id| cis2::Transfer {
                    token_id: token_id.clone(),
                    amount: cis2::TokenAmount::from(1u32),
                    from,
                    to: to.clone(),
                    data: to_func_data.clone(),
                })
                .collect();

            // The GRPC client for Concordium node.
            let mut grpc_client = Client::connect(app.endpoint, app.auth_token)
                .await
                .context("Failed to connect to Node GRPC")?;

            let cis2_contract_name = OwnedContractName::new_unchecked("init_CIS2-NFT".to_string());
            let mut cis2_contract =
                cis2::Cis2Contract::new(grpc_client.clone(), contract, cis2_contract_name);
            let next_account_nonce = grpc_client
                .get_next_account_nonce(&account_data.address)
                .await?;
            ensure!(
                next_account_nonce.all_final,
                "There are unfinalized transactions. Transaction nonce is not reliable enough."
            );
            let expiry = common::types::TransactionTime::from_seconds(
                (chrono::Utc::now().timestamp() + 300) as u64,
            );
            let energy = transactions::send::GivenEnergy::Add(energy.into());
            let amount = Amount::zero();
            eprintln!(
                "Transferring tokens {:?} from {} to {:?}",
                token_ids, from, to
            );

            let transaction_metadata = cis2::Cis2TransactionMetadata {
                sender_address: account_data.address,
                nonce: next_account_nonce.nonce,
                expiry,
                energy,
                amount,
            };

            let hash = cis2_contract
                .transfer(&account_data.account_keys, transaction_metadata, transfers)
                .await
                .context("CIS2 transfer failed")?;
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

/// Print the NFT contract state in a human readable format.
fn pretty_print_contract_state(state: &NFTContractState) {
    for (owner, address_state) in &state.state {
        println!("\n\n{}", owner);
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
    energy: transactions::send::GivenEnergy,
) -> anyhow::Result<types::hashes::TransactionHash> {
    let next_account_nonce = client.get_next_account_nonce(&account_data.address).await?;
    ensure!(
        next_account_nonce.all_final,
        "There are unfinalized transactions. Transaction nonce is not reliable enough."
    );
    let expiry =
        common::types::TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);
    let tx = transactions::send::make_and_sign_transaction(
        &account_data.account_keys,
        account_data.address,
        next_account_nonce.nonce,
        expiry,
        energy,
        payload,
    );
    let bi = transactions::BlockItem::AccountTransaction(tx);
    client
        .send_block_item(&bi)
        .await
        .context("Transaction was rejected by the node.")
}
