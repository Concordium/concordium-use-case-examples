use concordium_rust_sdk::types::smart_contracts::concordium_contracts_common::{
    deserial_vector_no_length, serial_vector_no_length, AccountAddress, Address, ContractAddress,
    Deserial, OwnedReceiveName, ParseError, Read, Serial, Write,
};
use std::{convert::TryFrom, fmt::Display, str::FromStr};
use thiserror::*;

/// CTS1 Amount of tokens.
pub type TokenAmount = u64;

/// CTS1 Token ID can be up to 255 bytes in size.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TokenIdVec(pub Vec<u8>);

/// Error from parsing a token ID bytes from a hex encoded string.
#[derive(Debug, Error)]
pub enum ParseTokenIdVecError {
    #[error("Invalid hex string: {0}")]
    ParseIntError(#[from] hex::FromHexError),
    #[error("Token ID too large. Maximum allowed size is 255 bytes. {0} bytes was provided.")]
    TooManyBytes(usize),
}

/// Parse a Token ID from a hex encoded string.
impl FromStr for TokenIdVec {
    type Err = ParseTokenIdVecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() > 255 {
            Err(ParseTokenIdVecError::TooManyBytes(bytes.len()))
        } else {
            Ok(TokenIdVec(bytes))
        }
    }
}

/// Display the token ID as a hex string.
impl std::fmt::Display for TokenIdVec {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))?;
        Ok(())
    }
}

/// Serialize the token ID according to CTS1 specification.
impl Serial for TokenIdVec {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// Deserialize bytes to a Token ID according to CTS1 specification.
impl Deserial for TokenIdVec {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let tokens_id_length = u8::deserial(source)?;
        let bytes = deserial_vector_no_length(source, tokens_id_length.into())?;
        Ok(TokenIdVec(bytes))
    }
}

/// The parameter for the NFT Contract function "CTS1-NFT.mint".
/// Important: this is specific to this NFT smart contract and contract
/// functions for minting are not part of the CTS1 specification.
#[derive(Debug)]
pub struct MintParams {
    pub owner:     Address,
    pub token_ids: Vec<TokenIdVec>,
}

/// Serialization for the minting contract function parameter.
/// Must match the serialization specified in the NFT smart contract.
impl Serial for MintParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.owner.serial(out)?;
        let len = u8::try_from(self.token_ids.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        for token in &self.token_ids {
            token.serial(out)?;
        }
        Ok(())
    }
}

/// Additional data bytes which can be included for each transfer in the
/// transfer parameter for the CTS1 contract function "transfer".
#[derive(Debug, Clone)]
pub struct AdditionalData {
    pub data: Vec<u8>,
}

/// Serialization for the additional data, serialized as according to the CTS1
/// specification.
impl Serial for AdditionalData {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u16::try_from(self.data.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        for byte in &self.data {
            byte.serial(out)?;
        }
        Ok(())
    }
}

/// Parse the additional data from a hex string.
impl FromStr for AdditionalData {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AdditionalData {
            data: hex::decode(s)?.to_vec(),
        })
    }
}

/// Address to receive an amount of tokens, it differs by the Address type by
/// additionally requiring a contract receive function name when the address is
/// a contract address.
#[derive(Debug, Clone)]
pub enum Receiver {
    Account(AccountAddress),
    Contract(ContractAddress, OwnedReceiveName),
}

impl Serial for Receiver {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Receiver::Account(address) => {
                0u8.serial(out)?;
                address.serial(out)
            }
            Receiver::Contract(address, receive_name) => {
                1u8.serial(out)?;
                address.serial(out)?;
                receive_name.as_ref().serial(out)
            }
        }
    }
}

/// A description of a transfer according to the CTS1 specification.
#[derive(Debug)]
pub struct Transfer {
    /// The ID of the token type to transfer.
    pub token_id: TokenIdVec,
    /// The amount of tokens to transfer.
    pub amount:   u64,
    /// The address currently owning the tokens being transferred.
    pub from:     Address,
    /// The receiver for the tokens being transferred.
    pub to:       Receiver,
    /// Additional data to include for the transfer
    pub data:     AdditionalData,
}

/// Serialization of a transfer, according to the CTS1 specification.
impl Serial for Transfer {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.token_id.serial(out)?;
        self.amount.serial(out)?;
        self.from.serial(out)?;
        self.to.serial(out)?;
        self.data.serial(out)?;
        Ok(())
    }
}

/// The parameter type for the NFT contract function `CTS1-NFT.transfer`.
#[derive(Debug)]
pub struct TransferParams(pub Vec<Transfer>);

/// Serialization of the transfer parameter, according to the CTS1
/// specification.
impl Serial for TransferParams {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = u8::try_from(self.0.len()).map_err(|_| W::Err::default())?;
        len.serial(out)?;
        serial_vector_no_length(&self.0, out)
    }
}

/// The type of update for an operator update.
#[derive(Debug, Clone, Copy)]
pub enum OperatorUpdate {
    /// Remove the operator.
    Remove,
    /// Add an address as an operator.
    Add,
}

/// The deserialization of an operator update, according to the CTS1
/// specification.
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

impl Display for OperatorUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let str = match self {
            OperatorUpdate::Remove => "Remove",
            OperatorUpdate::Add => "Add",
        };
        write!(f, "{}", str)
    }
}

type Sha256 = [u8; 32];

/// A URL for the metadata.
#[derive(Debug)]
pub struct MetadataUrl {
    /// The url encoded according to CTS1.
    pub url:  String,
    /// An optional checksum of the content found at the URL.
    pub hash: Option<Sha256>,
}

/// Deserialization for MetadataUrl according to the CTS1 specification.
impl Deserial for MetadataUrl {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let len = source.read_u16()?;
        let mut bytes = Vec::with_capacity(len.into());
        for _ in 0..len {
            bytes.push(source.read_u8()?)
        }
        let url = String::from_utf8(bytes)?;
        let hash = Option::<Sha256>::deserial(source)?;
        Ok(MetadataUrl { url, hash })
    }
}

/// Smart contract logged event, part of the CTS1 specification.
#[derive(Debug)]
pub enum Event {
    /// Transfer of an amount of tokens
    Transfer {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        from:     Address,
        to:       Address,
    },
    /// Minting an amount of tokens
    Mint {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    /// Burning an amount of tokens
    Burn {
        token_id: TokenIdVec,
        amount:   TokenAmount,
        owner:    Address,
    },
    /// Add/Remove an address as operator for some other address.
    UpdateOperator {
        update:   OperatorUpdate,
        owner:    Address,
        operator: Address,
    },
    /// Provide an URL with the metadata for a certain token.
    TokenMetadata {
        token_id:     TokenIdVec,
        metadata_url: MetadataUrl,
    },
    /// Custom event outside of the CTS1 specification.
    Unknown,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Event::Transfer {
                token_id,
                from,
                to,
                amount: _,
            } => {
                write!(
                    f,
                    "Transferred token with ID {} from {} to {}",
                    token_id,
                    address_display(from),
                    address_display(to)
                )?;
            }
            Event::Mint {
                token_id,
                amount: _,
                owner,
            } => {
                write!(
                    f,
                    "Minted token with ID {} for {}",
                    token_id,
                    address_display(owner)
                )?;
            }
            Event::Burn {
                token_id,
                amount: _,
                owner,
            } => {
                write!(
                    f,
                    "Burned token with ID {} for {}",
                    token_id,
                    address_display(owner)
                )?;
            }
            Event::UpdateOperator {
                update,
                owner,
                operator,
            } => {
                write!(
                    f,
                    "{} {} as operator for {}",
                    update,
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
                write!(f, "Unknown event: Event is not part of CTS1 specification")?;
            }
        }
        Ok(())
    }
}

/// Deserialize the contract events as according to the CTS1 specification.
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

/// Display the Address using either the display for account address or contract
/// address.
fn address_display(a: &Address) -> String {
    match a {
        Address::Account(addr) => format!("{}", addr),
        Address::Contract(addr) => format!("{}", addr),
    }
}
