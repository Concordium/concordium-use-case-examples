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

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use concordium_contracts_common::Deserial;
use concordium_rust_sdk::{
    endpoints::{Client, Endpoint},
    types::{
        self,
        smart_contracts::{
            concordium_contracts_common::{Get, ParseError, ParseResult, Read, Serial, Write},
            InstanceInfo,
        },
    },
};
use smart_contracts::concordium_contracts_common;
use std::{
    convert::{Into, TryFrom, TryInto},
    str::FromStr,
};
use thiserror::*;
use types::smart_contracts;

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
            .split_once(',')
            .ok_or(ParseContractAddressError::NoCommaError)?;
        let index = u64::from_str(index)?;
        let sub_index = u64::from_str(sub_index)?;
        Ok(ContractAddressWrapper(types::ContractAddress::new(
            types::ContractIndex { index },
            types::ContractSubIndex { sub_index },
        )))
    }
}

#[derive(Debug)]
struct StandardIdentifier {
    id: String,
}

#[derive(Debug, Error)]
enum NewStandardIdentifierError {
    #[error("Too many characters")]
    TooManyCharacters(usize),
    #[error("Contained non-ascii characters")]
    NonAscii,
}

impl StandardIdentifier {
    fn new(id: String) -> Result<Self, NewStandardIdentifierError> {
        if id.len() > 255 {
            return Err(NewStandardIdentifierError::TooManyCharacters(id.len()));
        }
        if !id.is_ascii() {
            return Err(NewStandardIdentifierError::NonAscii);
        }
        Ok(StandardIdentifier { id })
    }
}

impl FromStr for StandardIdentifier {
    type Err = NewStandardIdentifierError;

    fn from_str(id: &str) -> Result<Self, Self::Err> { StandardIdentifier::new(id.to_string()) }
}

impl Serial for StandardIdentifier {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u8(self.id.len().try_into().map_err(|_| W::Err::default())?)?;
        for query in self.id.bytes() {
            query.serial(out)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SupportsParameter {
    queries: Vec<StandardIdentifier>,
}

impl Serial for SupportsParameter {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u16(
            self.queries
                .len()
                .try_into()
                .map_err(|_| W::Err::default())?,
        )?;
        for query in self.queries.iter() {
            query.serial(out)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
enum SupportResult {
    NoSupport,
    Support,
    SupportBy(Vec<concordium_contracts_common::ContractAddress>),
}

impl Deserial for SupportResult {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let tag = source.read_u8()?;
        match tag {
            0 => Ok(SupportResult::NoSupport),
            1 => Ok(SupportResult::Support),
            2 => {
                let len = source.read_u16()?;
                let mut contracts = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    contracts.push(source.get()?);
                }
                Ok(SupportResult::SupportBy(contracts))
            }
            _ => Err(ParseError {}),
        }
    }
}

#[derive(Debug)]
struct SupportsResponse {
    results: Vec<SupportResult>,
}

impl Deserial for SupportsResponse {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len = source.read_u16()?;
        let mut results = Vec::with_capacity(len as usize);
        for _ in 0..len {
            results.push(source.get()?);
        }
        Ok(SupportsResponse { results })
    }
}

#[derive(Debug, Parser)]
struct Args {
    /// GRPC interface of the node.
    #[clap(long = "node", default_value = "http://localhost:10001")]
    endpoint: Endpoint,

    /// GRPC authentication token.
    #[clap(long = "rpc-auth-token", default_value = "rpcadmin")]
    auth_token: String,

    /// Contract address to query.
    #[clap(long)]
    contract: ContractAddressWrapper,

    /// Standard to query.
    #[clap(long)]
    standard: Vec<StandardIdentifier>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut client = Client::connect(args.endpoint, args.auth_token)
        .await
        .context("Failed to connect to Node GRPC")?;

    let consensus_status = client
        .get_consensus_status()
        .await
        .context("Failed to get the consensus status")?;

    let instance_info = client
        .get_instance_info(args.contract.0, &consensus_status.last_finalized_block)
        .await
        .context("Failed to find contract instance")?;

    let contract_init_name = if let InstanceInfo::V1 { name, .. } = instance_info {
        name
    } else {
        eprintln!("Only v1 smart contracts can be queried");
        return Ok(());
    };
    let contract_name = &Into::<&str>::into(&contract_init_name)[5..];

    let mut contract_context = smart_contracts::ContractContext::new(
        args.contract.0,
        smart_contracts::ReceiveName::try_from(format!("{}.supports", contract_name))
            .map_err(|e| anyhow!("Failed to construct receive name: {}", e))?,
    );

    let paramter = SupportsParameter {
        queries: args.standard,
    };
    contract_context.parameter =
        smart_contracts::Parameter::from(concordium_contracts_common::to_bytes(&paramter));

    let invoke_result = client
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

    let response: SupportsResponse = concordium_contracts_common::from_bytes(&model)
        .map_err(|_| anyhow!("Failed parsing contract state"))?;

    eprintln!("{:?}", response.results);
    Ok(())
}
