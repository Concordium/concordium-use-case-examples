use anyhow::*;
use clap::AppSettings;
use concordium_contracts_common::{
    to_bytes, AccountAddress, Address, Cursor, Deserial, OwnedReceiveName, ParseError, Read, Serial,
};
use concordium_rust_sdk::{
    common, constants,
    endpoints::{Client, Endpoint},
    id, postgres,
    postgres::DatabaseSummaryEntry,
    types,
};
use futures::{FutureExt, StreamExt, TryStreamExt};
use serde::*;
use smart_contracts::concordium_contracts_common;
use std::{
    collections::{BTreeMap as Map, BTreeSet as Set},
    convert::TryFrom,
    fmt::Display,
    path::PathBuf,
    str::FromStr,
};
use structopt::*;
use thiserror::*;
use types::{smart_contracts, transactions};

type TokenAmount = u64;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct TokenIdVec(Vec<u8>);

#[derive(Debug, Error)]
enum ParseTokenIdVecError {
    #[error("Failed to parse the hex: {0}")]
    ParseIntError(#[from] hex::FromHexError),
    #[error("To many bytes for a token ID")]
    ToManyBytes,
}

impl FromStr for TokenIdVec {
    type Err = ParseTokenIdVecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() > 255 {
            Err(ParseTokenIdVecError::ToManyBytes)
        } else {
            Ok(TokenIdVec(bytes))
        }
    }
}

/// Display the token ID as a hex string
impl std::fmt::Display for TokenIdVec {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))?;
        Ok(())
    }
}

impl Serial for TokenIdVec {
    fn serial<W: concordium_contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        for byte in &self.0 {
            byte.serial(out)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct AddressState {
    /// The tokens owned by this address.
    owned_tokens: Set<TokenIdVec>,
    /// The address which are currently enabled as operators for this address.
    operators:    Set<Address>,
}

#[derive(Debug)]
struct NFTContractState(Map<Address, AddressState>);

impl Deserial for TokenIdVec {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let tokens_id_length = u8::deserial(source)?;
        let mut bytes = Vec::with_capacity(tokens_id_length.into());
        for _ in 0..tokens_id_length {
            let byte = source.read_u8()?;
            bytes.push(byte);
        }
        Ok(TokenIdVec(bytes))
    }
}

impl Deserial for AddressState {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let owned_tokens_length = u16::deserial(source)?;
        let mut owned_tokens = Set::default();
        for _ in 0..owned_tokens_length {
            let k = TokenIdVec::deserial(source)?;
            owned_tokens.insert(k);
        }
        let operators_length = u8::deserial(source)?;
        let mut operators = Set::default();
        for _ in 0..operators_length {
            let k = Address::deserial(source)?;
            operators.insert(k);
        }
        Ok(AddressState {
            owned_tokens,
            operators,
        })
    }
}

impl Deserial for NFTContractState {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let length = u32::deserial(source)?;
        let mut state = Map::default();
        for _ in 0..length {
            let k = Address::deserial(source)?;
            let v = AddressState::deserial(source)?;
            state.insert(k, v);
        }
        Ok(NFTContractState(state))
    }
}

#[derive(Debug)]
struct ContractAddressWrapper(types::ContractAddress);

#[derive(Debug, Error)]
enum ParseContractAddressError {
    #[error("Failed to parse the index/subindex integer: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Missing comma separater between index and subindex")]
    NoCommaError,
}

impl FromStr for ContractAddressWrapper {
    type Err = ParseContractAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = &s[1..s.len() - 1];
        let (index, sub_index) = trimmed
            .split_once(",")
            .ok_or_else(|| ParseContractAddressError::NoCommaError)?;
        let index = u64::from_str(index)?;
        let sub_index = u64::from_str(sub_index)?;
        Ok(ContractAddressWrapper(types::ContractAddress::new(
            types::ContractIndex { index },
            types::ContractSubIndex { sub_index },
        )))
    }
}

impl Display for ContractAddressWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "<{},{}>", self.0.index.index, self.0.subindex.sub_index)
    }
}

#[derive(Debug)]
struct AddressWrapper(types::Address);

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

impl Display for AddressWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self.0 {
            types::Address::Account(a) => a.fmt(f),
            types::Address::Contract(c) => ContractAddressWrapper(c).fmt(f),
        }
    }
}

/// Helper to parse account keys.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountData {
    account_keys: id::types::AccountKeys,
    address:      id::types::AccountAddress,
}

#[derive(Debug)]
struct MintParams {
    owner:     Address,
    token_ids: Vec<TokenIdVec>,
}

impl Serial for MintParams {
    fn serial<W: concordium_contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.owner.serial(out)?;
        let len = u8::try_from(self.token_ids.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        for token in &self.token_ids {
            token.serial(out)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ReceiveHookData(Vec<u8>);

impl Serial for ReceiveHookData {
    fn serial<W: concordium_contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        for byte in &self.0 {
            byte.serial(out)?;
        }
        Ok(())
    }
}

impl FromStr for ReceiveHookData {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ReceiveHookData(hex::decode(s)?.to_vec()))
    }
}

#[derive(Debug)]
struct Transfer {
    token_id:     TokenIdVec,
    amount:       u64,
    from:         Address,
    to:           Address,
    receive_name: Option<OwnedReceiveName>,
    data:         ReceiveHookData,
}

impl Serial for Transfer {
    fn serial<W: concordium_contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.token_id.serial(out)?;
        self.amount.serial(out)?;
        self.from.serial(out)?;
        self.to.serial(out)?;
        if let Address::Contract(_) = self.to {
            self.receive_name
                .as_ref()
                .ok_or_else(W::Err::default)?
                .serial(out)?;
            self.data.serial(out)?;
        }
        Ok(())
    }
}

/// The parameter type for the contract function `transfer`.
#[derive(Debug)]
struct TransferParams(pub Vec<Transfer>);

impl Serial for TransferParams {
    fn serial<W: concordium_contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        for transfer in &self.0 {
            transfer.serial(out)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct OwnedReceiveNameWrapper(OwnedReceiveName);

impl FromStr for OwnedReceiveNameWrapper {
    type Err = concordium_contracts_common::NewReceiveNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(OwnedReceiveNameWrapper(OwnedReceiveName::new(
            s.to_string(),
        )?))
    }
}

enum OperatorUpdate {
    /// Remove the operator.
    Remove,
    /// Add an address as an operator.
    Add,
}

impl Deserial for OperatorUpdate {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let discriminant = source.read_u8()?;
        match discriminant {
            0 => Ok(OperatorUpdate::Remove),
            1 => Ok(OperatorUpdate::Add),
            _ => Err(ParseError::default()),
        }
    }
}

type Sha256 = [u8; 32];

struct MetadataUrl {
    url:  String,
    hash: Option<Sha256>,
}

impl Deserial for MetadataUrl {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let len = source.read_u16()?;
        let mut bytes = Vec::new();
        for _ in 0..len {
            bytes.push(source.read_u8()?)
        }
        let url = String::from_utf8(bytes)?; //.map_err(|e| ParseError::default())?
        let hash = Option::<Sha256>::deserial(source)?;
        Ok(MetadataUrl { url, hash })
    }
}

enum Event {
    Transfer {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        from:     Address,
        to:       Address,
    },
    Mint {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    Burn {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    UpdateOperator {
        update:   OperatorUpdate,
        owner:    Address,
        operator: Address,
    },
    TokenMetadata {
        token_id:     TokenIdVec,
        metadata_url: MetadataUrl,
    },
    Unknown,
}

fn address_display(a: &Address) -> String {
    match a {
        Address::Account(addr) => format!("{}", addr),
        Address::Contract(addr) => format!("{}", addr),
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Event::Transfer {
                token_id,
                from,
                to,
                amount,
            } => {
                if *amount > 0 {
                    write!(
                        f,
                        "Transferred token with ID {} from {} to {}",
                        token_id,
                        address_display(from),
                        address_display(to)
                    )?;
                }
            }
            Event::Mint {
                token_id,
                amount,
                owner,
            } => {
                if *amount > 0 {
                    write!(
                        f,
                        "Minted token with ID {} for {}",
                        token_id,
                        address_display(owner)
                    )?;
                }
            }
            Event::Burn {
                token_id,
                amount,
                owner,
            } => {
                if *amount > 0 {
                    write!(
                        f,
                        "Burned token with ID {} for {}",
                        token_id,
                        address_display(owner)
                    )?;
                }
            }
            Event::UpdateOperator {
                update,
                owner,
                operator,
            } => {
                let operation = match update {
                    OperatorUpdate::Remove => "Remove",
                    OperatorUpdate::Add => "Add",
                };
                write!(
                    f,
                    "{} {} as operator for {}",
                    operation,
                    address_display(operator),
                    address_display(owner)
                )?;
            }
            Event::TokenMetadata {
                token_id,
                metadata_url,
            } => {
                let hash = if let Some(hash) = metadata_url.hash {
                    format!("with hash {}", hex::encode(hash))
                } else {
                    "without hash".to_string()
                };
                write!(
                    f,
                    "Added metadata url {} ({}) for token with ID {}",
                    metadata_url.url, hash, token_id
                )?;
            }
            Event::Unknown => {
                write!(f, "Unknown event: Event was not part of CTS specification")?;
            }
        }
        Ok(())
    }
}

impl Deserial for Event {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let discriminant = u8::deserial(source)?;
        match discriminant {
            0 => Ok(Event::Transfer {
                token_id: TokenIdVec::deserial(source)?,
                amount:   TokenAmount::deserial(source)?,
                from:     Address::deserial(source)?,
                to:       Address::deserial(source)?,
            }),
            1 => Ok(Event::Mint {
                token_id: TokenIdVec::deserial(source)?,
                amount:   TokenAmount::deserial(source)?,
                owner:    Address::deserial(source)?,
            }),
            2 => Ok(Event::Burn {
                token_id: TokenIdVec::deserial(source)?,
                amount:   TokenAmount::deserial(source)?,
                owner:    Address::deserial(source)?,
            }),
            3 => Ok(Event::UpdateOperator {
                update:   OperatorUpdate::deserial(source)?,
                owner:    Address::deserial(source)?,
                operator: Address::deserial(source)?,
            }),
            4 => Ok(Event::TokenMetadata {
                token_id:     TokenIdVec::deserial(source)?,
                metadata_url: MetadataUrl::deserial(source)?,
            }),
            _ => Ok(Event::Unknown),
        }
    }
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
    #[structopt(long = "contract", help = "NFT contract address")]
    contract: ContractAddressWrapper,
    #[structopt(subcommand)]
    command:  Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(
        name = "show",
        help = "Prints all addresses owning tokens and a list of the token IDs they currently own."
    )]
    PrintState,
    #[structopt(
        name = "trace",
        help = "Prints all addresses owning tokens and a list of the token IDs they currently own."
    )]
    Trace {
        #[structopt(
            long = "db",
            default_value = "host=localhost dbname=nft_client_logging user=nft-client \
                             password=arstneio port=5432",
            help = "Database connection string."
        )]
        config: postgres::Config,
    },
    #[structopt(
        name = "mint",
        help = "Send mint transaction to NFT contract, with the given token IDs."
    )]
    Mint {
        #[structopt(
            name = "sender",
            long = "sender",
            help = "JSON file containing the account keys."
        )]
        sender:    PathBuf,
        #[structopt(help = "Token ID to mint in the contract.")]
        token_ids: Vec<TokenIdVec>,
    },
    #[structopt(name = "transfer", help = "Transfer one NFT to another address.")]
    Transfer {
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
        token_ids:    Vec<TokenIdVec>,
        #[structopt(
            name = "from",
            long = "from",
            help = "The current owner of the token being transferred."
        )]
        from:         AddressWrapper,
        #[structopt(
            name = "to",
            long = "to",
            help = "The address to receive the token being transferred."
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
        to_func_data: ReceiveHookData,
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

    // The GRPC client for Concordium node.
    let mut grpc_client = Client::connect(app.endpoint, "rpcadmin".to_string())
        .await
        .context("Failed to connect to Node GRPC")?;

    let contract_name = "CTS1-NFT";

    match app.command {
        Command::PrintState => {
            let consensus_status = grpc_client.get_consensus_status().await?;
            let instance_info = grpc_client
                .get_instance_info(app.contract.0, &consensus_status.best_block)
                .await?;
            let mut cursor = Cursor::new(instance_info.model);
            let state = NFTContractState::deserial(&mut cursor)
                .map_err(|_| anyhow!("Failed parsing contract state"))?;
            pretty_print_contract_state(&state);
        }
        Command::Trace { config } => {
            println!("Connecting to postgres");
            let (db_client, mut connection) = config.connect(postgres::NoTls).await?;

            let (tx, mut rx) = futures::channel::mpsc::unbounded();
            let stream = futures::stream::poll_fn(move |ctx| connection.poll_message(ctx))
                .map_err(|e| panic!("{}", e));

            let task = stream.forward(tx).map(|r| r.unwrap());
            tokio::spawn(task);

            println!("Setting up trigger and notifications.");
            db_client
                .batch_execute(
                    format!(
                        "
CREATE OR REPLACE FUNCTION pg_temp.notify_insert () RETURNS trigger as $psql$
    BEGIN
        IF NEW.index = {} AND NEW.subindex = {} THEN
            PERFORM pg_notify('contract_updates', NEW.summary::text);
        END IF;
        RETURN NEW;
    END;$psql$ LANGUAGE plpgsql;

CREATE TRIGGER notify_on_insert_into_cti AFTER INSERT ON cti FOR EACH ROW EXECUTE PROCEDURE \
                         pg_temp.notify_insert();

LISTEN contract_updates;
    ",
                        &app.contract.0.index.index, &app.contract.0.subindex.sub_index
                    )
                    .as_str(),
                )
                .await
                .context("notify_insert creation failed")?;
            println!("awaiting notifications");

            while let Some(x) = rx.next().await {
                println!("value {:?}", x);
                let notification = if let tokio_postgres::AsyncMessage::Notification(n) = x {
                    n
                } else {
                    continue;
                };
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

                if let DatabaseSummaryEntry::BlockItem(item) = summary {
                    if let types::BlockItemSummaryDetails::AccountTransaction(tx) = item.details {
                        if let types::AccountTransactionEffects::ContractUpdateIssued { effects } =
                            tx.effects
                        {
                            for effect in effects {
                                if let types::ContractTraceElement::Updated { data } = effect {
                                    if data.address == app.contract.0 {
                                        for event in data.events {
                                            let mut cursor = Cursor::new(event.bytes);
                                            let event = Event::deserial(&mut cursor)
                                                .map_err(|_| anyhow!("Failed parsing event"))?;
                                            println!("{}", event);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Command::Mint { sender, token_ids } => {
            let account_data: AccountData = serde_json::from_str(
                &std::fs::read_to_string(sender).context("Could not read the keys file.")?,
            )
            .context("Could not parse the accounts file.")?;

            // Convert id::types::Address to contracts_common::Address
            let mut address_bytes = [0u8; 32];
            address_bytes.copy_from_slice(account_data.address.as_ref());
            let owner = AccountAddress(address_bytes);

            let mint_parameter = MintParams {
                owner:     Address::Account(owner),
                token_ids: token_ids.clone(),
            };
            let bytes = to_bytes(&mint_parameter);

            let transaction_payload = transactions::Payload::Update {
                amount:       common::types::Amount::from(0),
                address:      app.contract.0,
                receive_name: smart_contracts::ReceiveName::try_from(format!(
                    "{}.mint",
                    contract_name
                ))
                .map_err(|e| anyhow!("Failed to parse receive name {}", e))?,
                message:      smart_contracts::Parameter { bytes },
            };
            println!("Minting tokens {:?}", token_ids);
            let hash =
                send_transaction(&mut grpc_client, &account_data, transaction_payload).await?;
            println!("Transaction send {}", hash);
        }
        Command::Transfer {
            sender,
            token_ids,
            from,
            to,
            to_func,
            to_func_data,
        } => {
            let account_data: AccountData = serde_json::from_str(
                &std::fs::read_to_string(sender).context("Could not read the keys file.")?,
            )
            .context("Could not parse the accounts file.")?;

            let transfers = token_ids
                .iter()
                .map(|token_id| Transfer {
                    token_id:     token_id.clone(),
                    amount:       1,
                    from:         convert_address(from.0.clone()),
                    to:           convert_address(to.0.clone()),
                    receive_name: to_func.as_ref().map(|wrapper| wrapper.clone().0),
                    data:         to_func_data.clone(),
                })
                .collect();

            let parameter = TransferParams(transfers);
            let bytes = to_bytes(&parameter);

            let transaction_payload = transactions::Payload::Update {
                amount:       common::types::Amount::from(0),
                address:      app.contract.0,
                receive_name: smart_contracts::ReceiveName::try_from(format!(
                    "{}.transfer",
                    contract_name
                ))
                .map_err(|e| anyhow!("Failed to parse receive name {}", e))?,
                message:      smart_contracts::Parameter { bytes },
            };
            println!(
                "Transferring tokens {:?} from {} to {:?}",
                token_ids, from, to
            );
            let hash =
                send_transaction(&mut grpc_client, &account_data, transaction_payload).await?;
            println!("Transaction send {}", hash);
        }
    }

    Ok(())
}

fn convert_account_address(
    account: &id::types::AccountAddress,
) -> concordium_contracts_common::AccountAddress {
    let mut address_bytes = [0u8; 32];
    address_bytes.copy_from_slice(account.as_ref());
    AccountAddress(address_bytes)
}

fn convert_contract_address(
    contract: &types::ContractAddress,
) -> concordium_contracts_common::ContractAddress {
    concordium_contracts_common::ContractAddress {
        index:    contract.index.index,
        subindex: contract.subindex.sub_index,
    }
}

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
    for (owner, address_state) in &state.0 {
        if address_state.owned_tokens.is_empty() && address_state.operators.is_empty() {
            continue;
        }
        match owner {
            Address::Account(addr) => println!("\n\n{}", addr),
            Address::Contract(addr) => println!("\n\n{}", addr),
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
        bail!("Transaction failed")
    }
}
