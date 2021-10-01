use std::path::PathBuf;

use clap::AppSettings;
use concordium_rust_sdk::endpoints;
use crypto_common::{types::CredentialIndex, SerdeDeserialize, SerdeSerialize};
use id::{id_prover::*, id_verifier::*, types::*, constants::AttributeKind};

use pedersen_scheme::Randomness as PedersenRandomness;
use structopt::StructOpt;

use bulletproofs::range_proof::RangeProof;
use curve_arithmetic::*;
use pairing::bls12_381::Bls12;
use rand::*;
use serde::de::DeserializeOwned;
use serde_json::to_writer_pretty;
use std::{
    default::Default,
    fmt::Debug,
    fs::File,
    io::{self, BufReader},
    marker::PhantomData,
    path::Path,
};

use dialoguer::Input;
use anyhow::Context;
pub type ExampleCurve = <Bls12 as Pairing>::G1;

pub type ExampleAttribute = AttributeKind;


#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
struct ImportedAccount<C: Curve>{
    address: AccountAddress,
    #[serde(rename = "commitmentsRandomness")]
    commitments_randomness: Option<CommitmentsRandomness<C>>
}

#[derive(Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
struct Attributes<C:Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(rename = "attributeList")]
    attribute_list: AttributeList<C::Scalar, AttributeType>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
struct ImportedIdentity<C: Curve, AttributeType: Attribute<C::Scalar>> {
    accounts: Vec<ImportedAccount<C>>,
    #[serde(rename = "identityObject")]
    identity_object: Attributes<C, AttributeType>
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
struct ImportedIdentities<C: Curve, AttributeType: Attribute<C::Scalar>> {
    identities: Vec<ImportedIdentity<C, AttributeType>>
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
struct Wallet<C:Curve, AttributeType: Attribute<C::Scalar>>{
    value: ImportedIdentities<C, AttributeType>
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
#[serde(tag = "type")]
pub enum Claim<C: Curve, AttributeType: Attribute<C::Scalar>> {
    AttributeOpening {
        #[serde(rename = "attributeTag")]
        attribute_tag: AttributeTag,
        attribute: AttributeType,
        proof: PedersenRandomness<C>,
    },
    AttributeInRange {
        #[serde(rename = "attributeTag")]
        attribute_tag: AttributeTag,
        lower: AttributeType,
        upper: AttributeType,
        proof: RangeProof<C>,
    },
    AccountOwnership {
        #[serde(skip)]
        phantom_data: PhantomData<(C, AttributeType)>,
    },
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
struct ClaimAboutAccount<C: Curve, AttributeType: Attribute<C::Scalar>> {
    account: AccountAddress,
    credential_index: CredentialIndex,
    claim: Claim<C, AttributeType>,
}

fn write_json_to_file<P: AsRef<Path>, T: SerdeSerialize>(filepath: P, v: &T) -> io::Result<()> {
    let file = File::create(filepath)?;
    Ok(to_writer_pretty(file, v)?)
}
fn read_json_from_file<P, T>(path: P) -> io::Result<T>
where
    P: AsRef<Path> + Debug,
    T: DeserializeOwned,
{
    let file = File::open(path)?;

    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

#[derive(StructOpt)]
enum IdClient {
    #[structopt(name = "prove-ownership", about = "Prove ownership of an account.")]
    ProveOwnership(ProveOwnership),
    #[structopt(name = "verify-claim", about = "Verify a claim given a proof.")]
    VerifyClaim(Box<VerifyClaim>),
    #[structopt(
        name = "prove-attribute-in-range",
        about = "Claim that an attribute lies in a range and produce a proof."
    )]
    ProveAttributeInRange(ProveAttributeInRange),
    #[structopt(
        name = "reveal-attribute",
        about = "Reveal an attribute inside a commitment."
    )]
    RevealAttribute(RevealAttribute),
    #[structopt(
        name = "claim-account-ownership",
        about = "Claim ownership of an account."
    )]
    ClaimAccountOwnership(ClaimAccountOwnership),
}

#[derive(StructOpt)]
struct ProveOwnership {
    #[structopt(
        long = "private-keys",
        help = "File containing private credential keys."
    )]
    private_keys: PathBuf,
    #[structopt(long = "account", help = "Account address-")]
    account: AccountAddress,
    #[structopt(long = "challenge", help = "File containing verifier's challenge.")]
    challenge: PathBuf,
    #[structopt(long = "out", help = "Path to output the proof to.")]
    out: PathBuf,
}

#[derive(StructOpt)]
struct ProveAttributeInRange {
    #[structopt(long = "account", help = "The prover's account address.")]
    account: AccountAddress,
    #[structopt(
        long = "credential-index",
        help = "The credential index of the relevant credential on the account."
    )]
    credential_index: CredentialIndex,
    #[structopt(
        long = "attribute-tag",
        help = "The attribute tag claimed to contain the value inside the commitment."
    )]
    attribute_tag: AttributeTag,
    #[structopt(
        long = "attribute",
        help = "The attribute value inside the commitment."
    )]
    attribute: ExampleAttribute,
    #[structopt(
        long = "upper",
        help = "The upper bound of the value inside the commitment."
    )]
    upper: ExampleAttribute,
    #[structopt(
        long = "lower",
        help = "The lower bound of the value inside the commitment."
    )]
    lower: ExampleAttribute,
    #[structopt(
        long = "randomness",
        help = "Path to file containing randomness used to produce to commitment."
    )]
    randomness: PathBuf,
    #[structopt(long = "proof-out", help = "Path to output proof to.")]
    out: PathBuf,
    #[structopt(long = "grpc")]
    endpoint: endpoints::Endpoint,
}

#[derive(StructOpt)]
struct RevealAttribute {
    #[structopt(long = "account", help = "The prover's account address.")]
    account: AccountAddress,
    #[structopt(
        long = "credential-index",
        help = "The credential index of the relevant credential on the account."
    )]
    credential_index: CredentialIndex,
    #[structopt(
        long = "attribute-tag",
        help = "The attribute tag claimed to contain the value inside the commitment."
    )]
    attribute_tag: AttributeTag,
    #[structopt(
        long = "attribute",
        help = "The attribute value inside the commitment.",
        required_unless = "wallet",
        conflicts_with = "wallet"
    )]
    attribute: Option<ExampleAttribute>,
    #[structopt(
        long = "randomness",
        help = "Path to file containing randomness used to produce to commitment.",
        required_unless = "wallet",
        conflicts_with = "wallet"
    )]
    randomness: Option<PathBuf>,
    #[structopt(
        long = "--wallet",
        help = "Path to file mobile wallet export.",
        required_unless = "randomness",
        conflicts_with = "randomness"
    )]
    wallet: Option<PathBuf>,
    #[structopt(long = "proof-out", help = "Path to output proof to.")]
    out: PathBuf,
}

#[derive(StructOpt)]
struct ClaimAccountOwnership {
    #[structopt(long = "account", help = "The prover's account address.")]
    account: AccountAddress,
    #[structopt(
        long = "credential-index",
        help = "The credential index of the relevant credential on the account."
    )]
    credential_index: CredentialIndex,
    #[structopt(long = "claim-out", help = "Path to output claim to.")]
    out: PathBuf,
}

#[derive(StructOpt)]
struct VerifyClaim {
    #[structopt(long = "grpc")]
    endpoint: endpoints::Endpoint,
    #[structopt(long = "claim", help = "The path to a file containing a claim.")]
    claim: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = IdClient::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let client = IdClient::from_clap(&matches);
    use IdClient::*;
    match client {
        ProveOwnership(po) => handle_prove_ownership(po),
        VerifyClaim(vc) => handle_verify_claim(*vc).await?,
        ProveAttributeInRange(pair) => handle_prove_attribute_in_range(pair).await?,
        RevealAttribute(ra) => handle_reveal_attribute(ra),
        ClaimAccountOwnership(cao) => handle_claim_ownership(cao),
    }
    Ok(())
}

async fn handle_verify_claim(vc: VerifyClaim) -> anyhow::Result<()> {
    let claim_about_account: ClaimAboutAccount<ExampleCurve, ExampleAttribute> =
        read_json_from_file(vc.claim)?;
    let mut client = endpoints::Client::connect(vc.endpoint, "rpcadmin".to_string()).await?;
    let consensus_info = client.get_consensus_status().await?;
    let global_context = client
        .get_cryptographic_parameters(&consensus_info.last_finalized_block)
        .await?;
    let acc_info = client
        .get_account_info(
            &claim_about_account.account,
            &consensus_info.last_finalized_block,
        )
        .await?;
    let credential = acc_info
        .account_credentials
        .get(&claim_about_account.credential_index)
        .expect("No credential on account with given index");
    use AccountCredentialWithoutProofs::*;
    let (maybe_commitments, public_keys) = match &credential.value {
        Initial { icdv, .. } => (None, &icdv.cred_account), // This should never happen
        Normal { commitments, cdv } => (Some(commitments), &cdv.cred_key_info),
    };
    match claim_about_account.claim {
        Claim::AttributeOpening {
            attribute_tag,
            attribute,
            proof,
        } => {
            let maybe_commitment = match maybe_commitments {
                Some(commitments) => commitments.cmm_attributes.get(&attribute_tag),
                _ => None,
            };
            if let Some(commitment) = maybe_commitment {
                let b = verify_attribute(
                    &global_context.on_chain_commitment_key,
                    &attribute,
                    &proof,
                    &commitment,
                );
                println!("Result: {}", b);
            } else {
                println!(
                    "No commitment to attribute {} on given account.",
                    attribute_tag
                );
            }
        }
        Claim::AttributeInRange {
            attribute_tag,
            lower,
            upper,
            proof,
        } => {
            let maybe_commitment = match maybe_commitments {
                Some(commitments) => commitments.cmm_attributes.get(&attribute_tag),
                _ => None,
            };
            if let Some(commitment) = maybe_commitment {
                let b = verify_attribute_range(
                    &global_context.on_chain_commitment_key,
                    &global_context.bulletproof_generators(),
                    &lower,
                    &upper,
                    &commitment,
                    &proof,
                );
                println!("Result: {}", b.is_ok());
            } else {
                println!(
                    "No commitment to attribute {} on given account.",
                    attribute_tag
                );
            }
        }
        Claim::AccountOwnership { .. } => {
            let mut challenge = [0u8; 32];
            rand::thread_rng().fill(&mut challenge[..]);
            let challenge_path = "ownership-challenge.json";
            write_json_to_file(&challenge_path, &challenge)?;
            println!("Wrote challenge to file. Give challenge to prover.");

            let path_to_proof: Option<PathBuf> = {
                let validator = |candidate: &String| -> Result<(), String> {
                    if std::path::Path::new(candidate).exists() {
                        Ok(())
                    } else {
                        Err(format!("File {} does not exist. Try again.", candidate))
                    }
                };

                let mut input = Input::new();
                input.with_prompt("Enter the path to the proof");
                // offer a default option if the file exists.
                if std::path::Path::new("ownership-proof.json").exists() {
                    input.default("ownership-proof.json".to_string());
                };
                input.validate_with(validator);
                match input.interact() {
                    Ok(x) => Some(PathBuf::from(x)),
                    Err(e) => {
                        eprintln!("{}", e);
                        None
                    }
                }
            };
            if let Some(path) = path_to_proof {
                let proof: AccountOwnershipProof = read_json_from_file(path)?;
                let b = verify_account_ownership(
                    &public_keys,
                    claim_about_account.account,
                    &challenge,
                    &proof,
                );
                println!("Result: {}", b);
            } else {
                println!("Path to proof not found.");
            }
        }
    };

    Ok(())
}

async fn handle_prove_attribute_in_range(pair: ProveAttributeInRange) -> anyhow::Result<()> {
    let mut client = endpoints::Client::connect(pair.endpoint, "rpcadmin".to_string()).await?;
    let consensus_info = client.get_consensus_status().await?;
    let global_ctx = client
        .get_cryptographic_parameters(&consensus_info.last_finalized_block)
        .await?;
    let randomness: PedersenRandomness<ExampleCurve> = read_json_from_file(pair.randomness)?;
    let proof = prove_attribute_in_range(
        &global_ctx.bulletproof_generators(),
        &global_ctx.on_chain_commitment_key,
        &pair.attribute,
        &pair.lower,
        &pair.upper,
        &randomness,
    );
    if let Some(proof) = proof {
        let claim = ClaimAboutAccount {
            account: pair.account,
            credential_index: pair.credential_index,
            claim: Claim::AttributeInRange {
                attribute_tag: pair.attribute_tag,
                lower: pair.lower,
                upper: pair.upper,
                proof,
            },
        };
        write_json_to_file(&pair.out, &claim)?;
    }
    Ok(())
}

fn read_attribute_and_randomness_from_wallet(account: AccountAddress, tag: AttributeTag, wallet: Wallet<ExampleCurve, ExampleAttribute>) -> Result<(AttributeKind, PedersenRandomness<ExampleCurve>), String> {
    let maybe_randomness : Option<(Attributes<ExampleCurve, ExampleAttribute>, CommitmentsRandomness<ExampleCurve>)> = {
        let mut found = None;
        for identity in wallet.value.identities {
            if let Some(acc) = identity.accounts.into_iter().find(|x| x.address == account) {
                if let Some(rand) = acc.commitments_randomness {
                    found = Some((identity.identity_object, rand));
                } else {
                    return Err(format!("Randomness for account {} not found in wallet import.", account));
                }
                break;
            }
        }
        found
    };
    let (attribute, randomness) = match maybe_randomness {
        Some((id,rand)) => {
            match (id.attribute_list.alist.get(&tag), rand.attributes_rand.get(&tag)) {
                (Some(a), Some(r)) => (a.clone(), r.clone()),
                (_, _) => {return Err(format!("Attribute randomness {} not found on account {} in wallet import.", tag, account));}
            }
        },
        None => {return Err(format!("Account {} not found in wallet.", account));}
    };
    Ok((attribute, randomness))
}

fn decrypt_wallet(file : PathBuf) -> anyhow::Result<Wallet<ExampleCurve, ExampleAttribute>> {
    let data = std::fs::read(&file).context("Cannot read wallet input file.")?;
    let parsed_data = serde_json::from_slice(&data)?;
    let pass = rpassword::read_password_from_tty(Some("Enter password to decrypt with: "))?;
    let plaintext = match crypto_common::encryption::decrypt(&pass.into(), &parsed_data) {
        Ok(pt) => pt,
        Err(_) => anyhow::bail!("Could not decrypt."),
    };
    match serde_json::from_slice(&plaintext) {
        Ok(wallet) => Ok(wallet),
        Err(e) => anyhow::bail!("Could not parse wallet: {}.",e)
    }
}

fn handle_reveal_attribute(ra: RevealAttribute) {
    let account = ra.account;
    let tag = ra.attribute_tag;
    let (attribute, randomness): (AttributeKind, PedersenRandomness<ExampleCurve>) =
        match (ra.attribute, ra.randomness, ra.wallet) {
            (Some(attribute), Some(randomness_file), _) => match read_json_from_file(randomness_file) {
                Ok(r) => (attribute, r),
                Err(e) => {
                    eprintln!("Could not parse randomness: {}. Terminating.", e);
                    return;
                }
            },
            (_, _, Some(wallet_file)) => {
                match decrypt_wallet(wallet_file){
                    Ok(wallet) => {
                        match read_attribute_and_randomness_from_wallet(account, tag, wallet) {
                            Ok(x) => x,
                            Err(e) => {
                                eprintln!("Could not parse wallet: {} Terminating.", e);
                                return;
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        return;
                    }
                }
            },
            (_, _, _) => panic!("Attribute and randomness, or wallet is needed."),
        };
    let proof = randomness;
    let claim = ClaimAboutAccount {
        account,
        credential_index: ra.credential_index,
        claim: Claim::AttributeOpening {
            attribute_tag: ra.attribute_tag,
            attribute,
            proof,
        },
    };
    if let Err(e) = write_json_to_file(&ra.out, &claim) {
        eprintln!("Could not output claim with proof: {}", e);
        return;
    }
}

fn handle_claim_ownership(cao: ClaimAccountOwnership) {
    let claim = ClaimAboutAccount {
        account: cao.account,
        credential_index: cao.credential_index,
        claim: Claim::<ExampleCurve, ExampleAttribute>::AccountOwnership {
            phantom_data: Default::default(),
        },
    };
    if let Err(e) = write_json_to_file(&cao.out, &claim) {
        eprintln!("Could not output claim with proof: {}", e);
        return;
    }
}

fn handle_prove_ownership(po: ProveOwnership) {
    let cred_data: CredentialData = match read_json_from_file(po.private_keys) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not parse credential data: {}. Terminating.", e);
            return;
        }
    };
    let challenge: [u8; 32] = match read_json_from_file(po.challenge) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Could not parse challenge: {}. Terminating.", e);
            return;
        }
    };

    let proof = prove_ownership_of_account(cred_data, po.account, &challenge);

    if let Err(e) = write_json_to_file(&po.out, &proof) {
        eprintln!("Could not output proof: {}", e);
        return;
    }
}
