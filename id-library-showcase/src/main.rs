use std::path::PathBuf;

use clap::AppSettings;
use concordium_rust_sdk::{
    common::{encryption, types::CredentialIndex, SerdeDeserialize, SerdeSerialize},
    endpoints,
    id::{
        constants::AttributeKind, curve_arithmetic::*, id_prover::*, id_verifier::*,
        pedersen_commitment::Randomness as PedersenRandomness, range_proof::RangeProof, types::*,
    },
};
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
use structopt::StructOpt;

use anyhow::Context;
use dialoguer::Input;
pub type ExampleCurve = <Bls12 as Pairing>::G1;

/// We provide the following examples for proving statements about the identity
/// behind an account:
/// - reveal an attribute
/// - prove that an attribute is in a range of the form [a, b)
/// - prove ownership of an account
///
/// For the first two, the randomness of the on-chain commitments are needed.
/// For the latter, the the private keys of credential holder are needed.
///
/// In the examples, it is possible to pass in randomness and private keys
/// directly when making proofs, but it is also supported to pass in a mobile
/// wallet export. It contains both the mentioned randomness and private keys.
///
/// A decrypted mobile wallet export is a JSON file, so below we define a
/// `Wallet` that can be parsed from such JSON. We only parse the JSON fields
/// needed in order to get the randomness and the private keys.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct ImportedAccount {
    address:                AccountAddress,
    commitments_randomness: Option<CommitmentsRandomness<ExampleCurve>>,
    account_keys:           AccountKeys,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct ImportedIdentity {
    accounts:        Vec<ImportedAccount>,
    identity_object: IdentityObject<Bls12, ExampleCurve, AttributeKind>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct ImportedIdentities {
    identities: Vec<ImportedIdentity>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct Wallet {
    value: ImportedIdentities,
}

/// We define a type `Claim` representing all kinds of statements that the user
/// can prove, so far the three statements above. A claim indicates what the
/// user claims that it can proof. Claims can contain proofs, if they can be
/// verified right away without further interaction with verifier, while it
/// might require interaction with the verifier to prove other claims.

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
#[serde(tag = "type")]
pub enum Claim<C: Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(rename_all = "camelCase")]
    AttributeOpening {
        attribute_tag: AttributeTag,
        attribute:     AttributeType,
        proof:         PedersenRandomness<C>,
    },
    #[serde(rename_all = "camelCase")]
    AttributeInRange {
        attribute_tag: AttributeTag,
        lower:         AttributeType,
        upper:         AttributeType,
        proof:         RangeProof<C>,
    },
    AccountOwnership {
        #[serde(skip)]
        phantom_data: PhantomData<(C, AttributeType)>,
    },
}

/// This type is for specifying which credential holder and which account a
/// claim is about.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
struct ClaimAboutAccount<C: Curve, AttributeType: Attribute<C::Scalar>> {
    account:          AccountAddress,
    credential_index: CredentialIndex,
    claim:            Claim<C, AttributeType>,
}

fn write_json_to_file<P: AsRef<Path>, T: SerdeSerialize>(filepath: P, v: &T) -> io::Result<()> {
    let file = File::create(filepath)?;
    Ok(to_writer_pretty(file, v)?)
}
fn read_json_from_file<P, T>(path: P) -> io::Result<T>
where
    P: AsRef<Path> + Debug,
    T: DeserializeOwned, {
    let file = File::open(path)?;

    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

/// The commands for proving the statements above and one command for verifying
/// any of them.
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
    ProveAttributeInRange(Box<ProveAttributeInRange>),
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

/// Command for proving ownership of an account. It is an interactive proof and
/// needs a challenge from the verifier. The private keys of the credential
/// holder can either be parsed in directly or read from a mobile wallet export.
#[derive(StructOpt)]
struct ProveOwnership {
    #[structopt(
        long = "private-keys",
        help = "File containing private credential keys.",
        required_unless = "wallet",
        conflicts_with = "wallet"
    )]
    private_keys:     Option<PathBuf>,
    #[structopt(
        long = "wallet",
        help = "Path to file mobile wallet export.",
        required_unless = "private-keys",
        conflicts_with = "private-keys"
    )]
    wallet:           Option<PathBuf>,
    #[structopt(
        long = "credential-index",
        help = "The credential index of the relevant credential on the account.",
        required_unless = "private-keys",
        conflicts_with = "private-keys"
    )]
    credential_index: Option<CredentialIndex>,
    #[structopt(long = "account", help = "Account address-")]
    account:          AccountAddress,
    #[structopt(long = "challenge", help = "File containing verifier's challenge.")]
    challenge:        PathBuf,
    #[structopt(long = "out", help = "Path to output the proof to.")]
    out:              PathBuf,
}

/// Command for proving that an attribute is in a range. The randomness can be
/// parsed in directly or read from a mobile wallet export.
#[derive(StructOpt)]
struct ProveAttributeInRange {
    #[structopt(long = "account", help = "The prover's account address.")]
    account:          AccountAddress,
    #[structopt(
        long = "credential-index",
        help = "The credential index of the relevant credential on the account."
    )]
    credential_index: CredentialIndex,
    #[structopt(
        long = "attribute-tag",
        help = "The attribute tag claimed to contain the value inside the commitment."
    )]
    attribute_tag:    AttributeTag,
    #[structopt(
        long = "attribute",
        help = "The attribute value inside the commitment.",
        required_unless = "wallet",
        conflicts_with = "wallet"
    )]
    attribute:        Option<AttributeKind>,
    #[structopt(
        long = "upper",
        help = "The upper bound of the value inside the commitment."
    )]
    upper:            AttributeKind,
    #[structopt(
        long = "lower",
        help = "The lower bound of the value inside the commitment."
    )]
    lower:            AttributeKind,
    #[structopt(
        long = "randomness",
        help = "Path to file containing randomness used to produce to commitment.",
        required_unless = "wallet",
        conflicts_with = "wallet"
    )]
    randomness:       Option<PathBuf>,
    #[structopt(
        long = "wallet",
        help = "Path to file mobile wallet export.",
        required_unless = "randomness",
        conflicts_with = "randomness"
    )]
    wallet:           Option<PathBuf>,
    #[structopt(long = "proof-out", help = "Path to output proof to.")]
    out:              PathBuf,
    #[structopt(long = "node")]
    endpoint:         endpoints::Endpoint,
}

/// Command for revealing an attribute. The randomness can be parsed in
/// directly or read from a mobile wallet export.
#[derive(StructOpt)]
struct RevealAttribute {
    #[structopt(long = "account", help = "The prover's account address.")]
    account:          AccountAddress,
    #[structopt(
        long = "credential-index",
        help = "The credential index of the relevant credential on the account."
    )]
    credential_index: CredentialIndex,
    #[structopt(
        long = "attribute-tag",
        help = "The attribute tag claimed to contain the value inside the commitment."
    )]
    attribute_tag:    AttributeTag,
    #[structopt(
        long = "attribute",
        help = "The attribute value inside the commitment.",
        required_unless = "wallet",
        conflicts_with = "wallet"
    )]
    attribute:        Option<AttributeKind>,
    #[structopt(
        long = "randomness",
        help = "Path to file containing randomness used to produce the commitment.",
        required_unless = "wallet",
        conflicts_with = "wallet"
    )]
    randomness:       Option<PathBuf>,
    #[structopt(
        long = "wallet",
        help = "Path to file mobile wallet export.",
        required_unless = "randomness",
        conflicts_with = "randomness"
    )]
    wallet:           Option<PathBuf>,
    #[structopt(long = "proof-out", help = "Path to output proof to.")]
    out:              PathBuf,
}

/// Command for claiming ownership of an account.
#[derive(StructOpt)]
struct ClaimAccountOwnership {
    #[structopt(long = "account", help = "The prover's account address.")]
    account:          AccountAddress,
    #[structopt(
        long = "credential-index",
        help = "The credential index of the relevant credential on the account."
    )]
    credential_index: CredentialIndex,
    #[structopt(long = "claim-out", help = "Path to output claim to.")]
    out:              PathBuf,
}

/// Command for veryfying claims.
#[derive(StructOpt)]
struct VerifyClaim {
    #[structopt(long = "node")]
    endpoint: endpoints::Endpoint,
    #[structopt(long = "claim", help = "The path to a file containing a claim.")]
    claim:    PathBuf,
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
        ProveOwnership(po) => handle_prove_ownership(po)?,
        VerifyClaim(vc) => handle_verify_claim(*vc).await?,
        ProveAttributeInRange(pair) => handle_prove_attribute_in_range(*pair).await?,
        RevealAttribute(ra) => handle_reveal_attribute(ra)?,
        ClaimAccountOwnership(cao) => handle_claim_ownership(cao)?,
    }
    Ok(())
}

async fn handle_verify_claim(vc: VerifyClaim) -> anyhow::Result<()> {
    let claim_about_account: ClaimAboutAccount<ExampleCurve, AttributeKind> =
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
        .await?; // Read account info from chain.
    let credential = acc_info
        .account_credentials
        .get(&claim_about_account.credential_index)
        .expect("No credential on account with given index"); // Read the relevant credential from chain that the claim is about.
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
            // If the user claims that the value inside the on-chain commitment is
            // `attribute`, check that provided proof.
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
            // If the user claims that the value inside the on-chain commitment is in the
            // range [lower, upper), check that provided proof.
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
            // If the user claims to own the account, give the user a challenge and wait for
            // a proof.
            let mut challenge = [0u8; 32];
            rand::thread_rng().fill(&mut challenge[..]);
            let challenge_path = "ownership-challenge.json";
            write_json_to_file(&challenge_path, &challenge)?;
            println!(
                "Wrote challenge to file {}. Give challenge to prover.",
                challenge_path
            );

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
                // Check the proof that the user came back with.
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

fn read_attribute_and_randomness(
    account: AccountAddress,
    attribute_tag: AttributeTag,
    maybe_attribute: Option<AttributeKind>,
    maybe_randomness: Option<PathBuf>,
    maybe_wallet: Option<PathBuf>,
) -> anyhow::Result<(AttributeKind, PedersenRandomness<ExampleCurve>)> {
    match (maybe_attribute, maybe_randomness, maybe_wallet) {
        (Some(attribute), Some(randomness_file), _) => Ok((
            attribute,
            read_json_from_file(randomness_file)
                .context("Could not parse file with randomness.")?,
        )),
        (_, _, Some(wallet_file)) => {
            // Otherwise, use an exported mobile wallet.
            let wallet = decrypt_wallet(wallet_file)?;
            read_attribute_and_randomness_from_wallet(account, attribute_tag, wallet)
                .context("Could not parse wallet file.")
        }
        (_, _, _) => anyhow::bail!("Attribute and randomness, or wallet is needed."),
    }
}

/// Prove that an attribute on an account is in a range using provided
/// randomness (either directly or from wallet export).
async fn handle_prove_attribute_in_range(pair: ProveAttributeInRange) -> anyhow::Result<()> {
    let account = pair.account;
    let attribute_tag = pair.attribute_tag;
    let mut client = endpoints::Client::connect(pair.endpoint, "rpcadmin".to_string()).await?;
    let consensus_info = client.get_consensus_status().await?;
    let global_ctx = client
        .get_cryptographic_parameters(&consensus_info.last_finalized_block)
        .await?; // Read cryptographic parameters from chain that are needed for range proofs.
                 // Read attribute randomness directly, if they are provided, or from mobile
                 // wallet export.
    let (attribute, randomness) = read_attribute_and_randomness(
        account,
        attribute_tag,
        pair.attribute,
        pair.randomness,
        pair.wallet,
    )?;
    let proof = prove_attribute_in_range(
        &global_ctx.bulletproof_generators(),
        &global_ctx.on_chain_commitment_key,
        &attribute,
        &pair.lower,
        &pair.upper,
        &randomness,
    );
    if let Some(proof) = proof {
        let claim = ClaimAboutAccount {
            account,
            credential_index: pair.credential_index,
            claim: Claim::AttributeInRange {
                attribute_tag,
                lower: pair.lower,
                upper: pair.upper,
                proof,
            },
        };
        write_json_to_file(&pair.out, &claim)?;
        println!("Wrote claim with proof to {}.", pair.out.display());
    } else {
        anyhow::bail!("Could not produce proof.");
    }
    Ok(())
}

fn read_attribute_and_randomness_from_wallet(
    account: AccountAddress,
    tag: AttributeTag,
    wallet: Wallet,
) -> anyhow::Result<(AttributeKind, PedersenRandomness<ExampleCurve>)> {
    let maybe_randomness: Option<(
        IdentityObject<Bls12, ExampleCurve, AttributeKind>,
        CommitmentsRandomness<ExampleCurve>,
    )> = {
        let mut found = None;
        // Look for given account in the wallet. If it exists,
        // remember the identity and the randomness.
        for identity in wallet.value.identities {
            if let Some(acc) = identity.accounts.into_iter().find(|x| x.address == account) {
                if let Some(rand) = acc.commitments_randomness {
                    found = Some((identity.identity_object, rand));
                } else {
                    anyhow::bail!(
                        "Randomness for account {} not found in wallet import.",
                        account
                    );
                }
                break;
            }
        }
        found
    };
    let (id, rand) =
        maybe_randomness.context(format!("Account {} not found in wallet.", account))?;
    // Look up the attribute from the identity found above.
    let attribute = id.alist.alist.get(&tag).context(format!(
        "No attribute with tag {} found on account {} in wallet.",
        tag, account
    ))?;
    // Look up the concrete randomness for the given attribute tag in the randomness
    // found above.
    let randomness = rand.attributes_rand.get(&tag).context(format!(
        "Attribute randomness for attribute {} not found on account {} in wallet.",
        tag, account
    ))?;
    Ok((attribute.clone(), randomness.clone()))
}

fn read_account_keys_from_wallet(
    account: AccountAddress,
    wallet: &Wallet,
) -> anyhow::Result<&AccountKeys> {
    // Look for the given account in the wallet, and if it exists, return the keys.
    for identity in wallet.value.identities.iter() {
        if let Some(acc) = identity.accounts.iter().find(|x| x.address == account) {
            return Ok(&acc.account_keys);
        }
    }
    anyhow::bail!("Account {} not found in wallet.", account)
}

/// Function for decrypting the mobile wallet export file. Same password as
/// chosen when exporting in the mobile wallet.
fn decrypt_wallet(file: PathBuf) -> anyhow::Result<Wallet> {
    let data = std::fs::read(&file).context("Cannot read wallet input file.")?;
    let parsed_data = serde_json::from_slice(&data)?;
    let pass = rpassword::read_password_from_tty(Some("Enter password to decrypt with: "))?;
    let plaintext =
        encryption::decrypt(&pass.into(), &parsed_data).context("Could not decrypt wallet.")?;
    serde_json::from_slice(&plaintext).context("Could not parse decrypted wallet.")
}

/// Reveal an attribute on an account using provided randomness (either directly
/// or from wallet export).
fn handle_reveal_attribute(ra: RevealAttribute) -> anyhow::Result<()> {
    let account = ra.account;
    let attribute_tag = ra.attribute_tag;
    let (attribute, randomness) = read_attribute_and_randomness(
        account,
        attribute_tag,
        ra.attribute,
        ra.randomness,
        ra.wallet,
    )?;
    let proof = randomness;
    let claim = ClaimAboutAccount {
        account,
        credential_index: ra.credential_index,
        claim: Claim::AttributeOpening {
            attribute_tag,
            attribute,
            proof,
        },
    };
    write_json_to_file(&ra.out, &claim).context("Could not output claim with proof.")?;
    println!("Wrote claim with proof to {:?}.", ra.out);
    Ok(())
}

/// Claim ownership of an account. Contains no proof.
fn handle_claim_ownership(cao: ClaimAccountOwnership) -> anyhow::Result<()> {
    let claim = ClaimAboutAccount {
        account:          cao.account,
        credential_index: cao.credential_index,
        claim:            Claim::<ExampleCurve, AttributeKind>::AccountOwnership {
            phantom_data: Default::default(),
        },
    };
    write_json_to_file(&cao.out, &claim).context("Could not output claim.")?;
    println!("Wrote claim to {}.", cao.out.display());
    Ok(())
}

/// Given a challenge from the verifier, prove ownership of an account using the
/// private keys of the credential holder, provided either directly or from
/// wallet export.
fn handle_prove_ownership(po: ProveOwnership) -> anyhow::Result<()> {
    let challenge: [u8; 32] =
        read_json_from_file(po.challenge).context("Could not parse challenge.")?;
    let proof: AccountOwnershipProof = match (po.private_keys, po.wallet, po.credential_index) {
        (Some(file), _, _) => {
            // Use credential keys if they are provided.
            let cred_data: CredentialData =
                read_json_from_file(file).context("Could not parse credential data")?;
            prove_ownership_of_account(&cred_data, po.account, &challenge)
        }
        (_, Some(wallet_file), Some(index)) => {
            // Otherwise, read keys from provided wallet export.
            let wallet = decrypt_wallet(wallet_file)?;
            let account_keys = read_account_keys_from_wallet(po.account, &wallet)
                .context("Could not parse wallet")?;
            let cred_data = account_keys
                .keys
                .get(&index)
                .context("Provided wallet contains no keys for given credential index.")?;
            prove_ownership_of_account(cred_data, po.account, &challenge)
        }
        (_, _, _) => {
            anyhow::bail!("No private keys provided.");
        }
    };

    write_json_to_file(&po.out, &proof).context("Could not output proof.")?;
    println!("Wrote proof to {:?}.", po.out);
    Ok(())
}
