use anyhow::Context;
use chrono::{DateTime, NaiveDateTime, Utc};
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{types::*, *},
    elgamal, encrypted_transfers, id,
    id::types::*,
    postgres::{DatabaseClient, QueryOrder, *},
    types::*,
};
use futures::*;
use serde::de::DeserializeOwned;
use std::{
    fmt::Debug,
    fs::File,
    io::{self, BufReader},
    path::*,
};
use structopt::StructOpt;
use tokio_postgres::NoTls;

#[derive(Debug)]
pub enum AmountDelta {
    PositiveAmount(Amount),
    NegativeAmount(Amount),
}

impl std::fmt::Display for AmountDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmountDelta::PositiveAmount(a) => write!(f, "+{}", a),
            AmountDelta::NegativeAmount(a) => write!(f, "-{}", a),
        }
    }
}

impl<'de> SerdeDeserialize<'de> for AmountDelta {
    fn deserialize<D: serde::de::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        use std::convert::TryInto;
        let s = String::deserialize(des)?;
        let n = s
            .parse::<i128>()
            .map_err(|e| D::Error::custom(format!("Could not parse amount delta: {}", e)))?;
        if n >= 0 {
            let microgtu: u64 = n
                .try_into()
                .map_err(|_| D::Error::custom("Amount delta out of range."))?;
            Ok(AmountDelta::PositiveAmount(Amount::from(microgtu)))
        } else {
            let m = n
                .checked_abs()
                .ok_or_else(|| D::Error::custom("Amount delta out of range."))?;
            let microgtu: u64 = m
                .try_into()
                .map_err(|_| D::Error::custom("Amount delta out of range."))?;
            Ok(AmountDelta::NegativeAmount(Amount::from(microgtu)))
        }
    }
}
pub fn read_json_from_file<P, T>(path: P) -> io::Result<T>
where
    P: AsRef<Path> + Debug,
    T: DeserializeOwned, {
    let file = File::open(path)?;

    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

/// Should match what's output by the anonymity_revocation tool.
#[derive(SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct RetrievalInput {
    account_address:       AccountAddress,
    /// An optional secret key. If present amounts will be decrypted, otherwise
    /// they will not.
    encryption_secret_key: Option<elgamal::SecretKey<id::constants::ArCurve>>,
}

#[derive(StructOpt)]
/// Mode of operation, either decrypt all, or just one.
enum Mode {
    #[structopt(about = "Trace all accounts in the given file.", name = "all")]
    All {
        #[structopt(
            help = "File with data about the account we need to decrypt.",
            long = "regids",
            default_value = "regids.json"
        )]
        regids_file: PathBuf,
    },
    #[structopt(about = "Trace a single account.", name = "single")]
    Single {
        #[structopt(help = "Account address to trace.", long = "address")]
        address:        AccountAddress,
        #[structopt(
            help = "Optionally a decryption key to decrypt encrypted transfers.",
            long = "decryption-key"
        )]
        decryption_key: Option<String>,
    },
}

#[derive(StructOpt)]
struct Trace {
    #[structopt(
        long = "global",
        help = "File with cryptographic parameters.",
        default_value = "global.json"
    )]
    global: PathBuf,
    #[structopt(
        long = "out",
        help = "File to output the account trace to. If not provided the data is printed to \
                stdout."
    )]
    out:    Option<PathBuf>,
    #[structopt(
        long = "db",
        default_value = "host=localhost dbname=transaction-outcome user=postgres \
                         password=password port=5432",
        help = "Database connection string."
    )]
    config: tokio_postgres::Config,
    #[structopt(subcommand)]
    mode:   Mode,
}

#[tokio::main]
async fn main() {
    let app = Trace::clap()
        .setting(AppSettings::ArgRequiredElseHelp)
        .global_setting(AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let tr = Trace::from_clap(&matches);
    let global: GlobalContext<id::constants::ArCurve> =
        match read_json_from_file::<_, Versioned<GlobalContext<_>>>(&tr.global) {
            Ok(global) if global.version == VERSION_0 => global.value,
            Ok(global) => {
                eprintln!(
                    "Cryptographic parameters have an unsupported version tag {}",
                    global.version
                );
                return;
            }
            Err(e) => {
                eprintln!("Could not read cryptographic parameters {}", e);
                return;
            }
        };
    let table = elgamal::BabyStepGiantStep::new(global.encryption_in_exponent_generator(), 1 << 16);
    let db = match DatabaseClient::create(tr.config, NoTls).await {
        Ok(db) => db,
        Err(e) => panic!("Connection to database failed: {}", e),
    };
    let mut writer: Box<dyn std::io::Write> = if let Some(file) = tr.out {
        Box::new(std::fs::File::create(file).expect("Cannot create output file"))
    } else {
        Box::new(std::io::stdout())
    };
    match tr.mode {
        Mode::All { regids_file } => {
            let inputs: Vec<RetrievalInput> = match read_json_from_file(regids_file) {
                Ok(data) => data,
                Err(_) => {
                    eprintln!("Could not read regids from the provided file.");
                    return;
                }
            };
            for input in inputs.iter() {
                trace_single_account(&table, &db, input, &mut writer).await;
                writeln!(writer, "\n\n").expect("Could not write.");
            }
        }
        Mode::Single {
            address,
            decryption_key,
        } => {
            let input = match decryption_key {
                Some(decryption_key) => {
                    let encryption_secret_key = match hex::decode(&decryption_key)
                        .context("Hex decoding error")
                        .and_then(|bs| from_bytes(&mut std::io::Cursor::new(bs)))
                    {
                        Ok(v) => Some(v),
                        Err(e) => {
                            eprintln!("The provided decryption key is malformed due to: {}", e);
                            return;
                        }
                    };
                    RetrievalInput {
                        account_address: address,
                        encryption_secret_key,
                    }
                }
                None => RetrievalInput {
                    account_address:       address,
                    encryption_secret_key: None,
                },
            };
            trace_single_account(&table, &db, &input, &mut writer).await;
        }
    };
}

// Columns in CSV:
// Timestamp
// Transaction or Reward Type
// Sender
// Receiver
// Cost
// Reward
// Amount
// ...

async fn trace_single_account(
    table: &elgamal::BabyStepGiantStep<id::constants::ArCurve>,
    db: &DatabaseClient,
    input: &RetrievalInput,
    _writer: &mut impl std::io::Write,
) {
    let traced_account = input.account_address;
    let rows = match db
        .query_account(&traced_account, 10000, QueryOrder::Ascending {
            start: None,
        })
        .await
    {
        Ok(rows) => rows,
        Err(e) => panic!("Could not retrieve rows: {}", e),
    };
    println!("Tracing: {}.", traced_account);
    rows.for_each(|entry| async move {
        let timestamp = entry.block_time;
        match entry.summary {
            DatabaseSummaryEntry::BlockItem(bis) => {
                match bis.details {
                    BlockItemSummaryDetails::AccountTransaction(at) => {
                        let sender = at.sender;
                        let cost = if sender == traced_account {
                            Some(at.cost)
                        } else {
                            None
                        };
                        match at.effects {
                            AccountTransactionEffects::None {
                                transaction_type, ..
                            } => match transaction_type {
                                None => {
                                    println!(
                                        "Time: {} Sender: {} Cost: {:?} Type: unknown",
                                        pretty_time(timestamp),
                                        sender,
                                        cost
                                    );
                                }
                                Some(transaction_type) => {
                                    println!(
                                        "Time: {} Sender: {} Cost: {:?} Type: {:?}",
                                        pretty_time(timestamp),
                                        sender,
                                        cost,
                                        transaction_type
                                    );
                                }
                            },
                            AccountTransactionEffects::ModuleDeployed { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::ContractInitialized { data } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}, Amount: {}",
                                    pretty_time(timestamp),
                                    sender,
                                    cost,
                                    AmountDelta::NegativeAmount(data.amount)
                                );
                            }
                            AccountTransactionEffects::ContractUpdateIssued { effects } => {
                                let mut added_to_account = 0_u64;
                                let mut taken_from_account = 0_u64;
                                for eff in effects {
                                    match eff {
                                        ContractTraceElement::Updated { data } => {
                                            // If effect took money from an account
                                            if let Address::Account(instigator) = data.instigator {
                                                // If the account was the current account
                                                if instigator == traced_account {
                                                    taken_from_account += data.amount.microgtu;
                                                }
                                            }
                                        }
                                        ContractTraceElement::Transferred {
                                            from: _,
                                            amount,
                                            to,
                                        } => {
                                            if to == traced_account {
                                                added_to_account += amount.microgtu;
                                            }
                                        }
                                    }
                                }
                                let amount_total = if taken_from_account > added_to_account {
                                    AmountDelta::NegativeAmount(Amount::from(
                                        taken_from_account - added_to_account,
                                    ))
                                } else {
                                    AmountDelta::PositiveAmount(Amount::from(
                                        added_to_account - taken_from_account,
                                    ))
                                };
                                println!(
                                    "Time: {} Sender: {} Cost: {:?} Amount: {}",
                                    pretty_time(timestamp),
                                    sender,
                                    cost,
                                    amount_total
                                );
                            }
                            AccountTransactionEffects::AccountTransfer { amount, to } => {
                                println!(
                                    "Time: {} Sender: {} Receiver: {} Cost: {:?}, Amount: {}, \
                                     Type: AccountTransfer",
                                    pretty_time(timestamp),
                                    sender,
                                    to,
                                    cost,
                                    if sender == traced_account {
                                        AmountDelta::NegativeAmount(amount)
                                    } else {
                                        AmountDelta::PositiveAmount(amount)
                                    }
                                );
                            }
                            AccountTransactionEffects::AccountTransferWithMemo {
                                amount,
                                to,
                                ..
                            } => {
                                println!(
                                    "Time: {} Sender: {} Receiver: {} Cost: {:?}, Amount: {}, \
                                     Type: AccountTransferWithMemo",
                                    pretty_time(timestamp),
                                    sender,
                                    to,
                                    cost,
                                    if sender == traced_account {
                                        AmountDelta::NegativeAmount(amount)
                                    } else {
                                        AmountDelta::PositiveAmount(amount)
                                    }
                                );
                            }
                            AccountTransactionEffects::BakerAdded { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?},  Type: BakerAdded",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::BakerRemoved { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}, Type: Baker removed",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::BakerStakeUpdated { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}, Type: BakerAdded",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::BakerRestakeEarningsUpdated { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}, Type: \
                                     BakerRestakeEarningsUpdated",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::BakerKeysUpdated { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}, Type: BakerKeysUpdated",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::EncryptedAmountTransferred {
                                removed,
                                added,
                            } => {
                                let receiver = added.receiver;
                                if let Some(key) = &input.encryption_secret_key {
                                    let delta = if sender == traced_account {
                                        let before = encrypted_transfers::decrypt_amount(
                                            table,
                                            key,
                                            &removed.input_amount,
                                        );
                                        let after = encrypted_transfers::decrypt_amount(
                                            table,
                                            key,
                                            &removed.new_amount,
                                        );
                                        assert!(before >= after);
                                        AmountDelta::NegativeAmount(Amount::from(
                                            before.microgtu - after.microgtu,
                                        ))
                                    } else {
                                        let amount_received = encrypted_transfers::decrypt_amount(
                                            table,
                                            key,
                                            &added.encrypted_amount,
                                        );
                                        AmountDelta::PositiveAmount(amount_received)
                                    };
                                    println!(
                                        "Time: {} Sender: {} Receiver {} Cost: {:?} Amount: {} \
                                         Type: EncryptedTransfer",
                                        pretty_time(timestamp),
                                        sender,
                                        receiver,
                                        cost,
                                        delta
                                    );
                                } else {
                                    println!(
                                        "Time: {} Sender: {} Receiver {} Cost: {:?} Type: \
                                         EncryptedTransfer",
                                        pretty_time(timestamp),
                                        sender,
                                        receiver,
                                        cost
                                    );
                                }
                            }
                            AccountTransactionEffects::EncryptedAmountTransferredWithMemo {
                                added,
                                removed,
                                ..
                            } => {
                                let receiver = added.receiver;
                                if let Some(key) = &input.encryption_secret_key {
                                    let delta = if sender == traced_account {
                                        let before = encrypted_transfers::decrypt_amount(
                                            table,
                                            key,
                                            &removed.input_amount,
                                        );
                                        let after = encrypted_transfers::decrypt_amount(
                                            table,
                                            key,
                                            &removed.new_amount,
                                        );
                                        assert!(before >= after);
                                        AmountDelta::NegativeAmount(Amount::from(
                                            before.microgtu - after.microgtu,
                                        ))
                                    } else {
                                        let amount_received = encrypted_transfers::decrypt_amount(
                                            table,
                                            key,
                                            &added.encrypted_amount,
                                        );
                                        AmountDelta::PositiveAmount(amount_received)
                                    };
                                    println!(
                                        "Time: {} Sender: {} Receiver {} Cost: {:?} Amount: {} \
                                         Type: EncryptedTransferWithMemo",
                                        pretty_time(timestamp),
                                        sender,
                                        receiver,
                                        cost,
                                        delta
                                    );
                                } else {
                                    println!(
                                        "Time: {} Sender: {} Receiver {} Cost: {:?} Type: \
                                         EncryptedTransferWithMemo",
                                        pretty_time(timestamp),
                                        sender,
                                        receiver,
                                        cost
                                    );
                                }
                            }
                            AccountTransactionEffects::TransferredToEncrypted { data } => {
                                // todo I put a decrease in amount, since this much less money is
                                // now in the public balance.
                                println!(
                                    "Time: {} Sender: {} Cost: {:?} Amount: {} Type: \
                                     TransferredToEncrypted",
                                    pretty_time(timestamp),
                                    sender,
                                    cost,
                                    AmountDelta::NegativeAmount(data.amount)
                                );
                            }
                            AccountTransactionEffects::TransferredToPublic { amount, .. } => {
                                // todo I put an increase in amount, since this much extra money is
                                // now in the public balance.
                                println!(
                                    "Time: {} Sender: {} Cost: {:?} Amount: {} Type: \
                                     TransferredToPublic",
                                    pretty_time(timestamp),
                                    sender,
                                    cost,
                                    AmountDelta::PositiveAmount(amount)
                                );
                            }
                            AccountTransactionEffects::TransferredWithSchedule { to, amount } => {
                                let mut sum = 0;
                                for (_, am) in amount {
                                    sum += am.microgtu;
                                }
                                println!(
                                    "Time: {} Sender: {} Receiver: {} Cost: {:?} Amount: {} Type: \
                                     TransferWithSchedule",
                                    pretty_time(timestamp),
                                    sender,
                                    to,
                                    cost,
                                    if sender == traced_account {
                                        AmountDelta::NegativeAmount(Amount::from(sum))
                                    } else {
                                        AmountDelta::PositiveAmount(Amount::from(sum))
                                    }
                                );
                            }
                            AccountTransactionEffects::TransferredWithScheduleAndMemo {
                                to,
                                amount,
                                ..
                            } => {
                                let mut sum = 0;
                                for (_, am) in amount {
                                    sum += am.microgtu;
                                }
                                println!(
                                    "Time: {} Sender: {} Receiver: {} Cost: {:?} Amount: {} Type: \
                                     TransferWithScheduleAndMemo",
                                    pretty_time(timestamp),
                                    sender,
                                    to,
                                    cost,
                                    if sender == traced_account {
                                        AmountDelta::NegativeAmount(Amount::from(sum))
                                    } else {
                                        AmountDelta::PositiveAmount(Amount::from(sum))
                                    }
                                );
                            }
                            AccountTransactionEffects::CredentialKeysUpdated { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?} Type: CredentialKeysUpdated",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::CredentialsUpdated { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}, Type: CredentialsUpdated",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                            AccountTransactionEffects::DataRegistered { .. } => {
                                println!(
                                    "Time: {} Sender: {} Cost: {:?}, Type: DataRegistered",
                                    pretty_time(timestamp),
                                    sender,
                                    cost
                                );
                            }
                        }
                    }
                    BlockItemSummaryDetails::AccountCreation(_) => {
                        // TODO: I think this can be ignored.
                    }
                    BlockItemSummaryDetails::Update(_) => {
                        // A protocol update is a free transaction, it does not
                        // affect any accounts directly.
                    }
                }
            }
            DatabaseSummaryEntry::ProtocolEvent(sto) => {
                match sto {
                    SpecialTransactionOutcome::BakingRewards { baker_rewards, .. } => {
                        // The reward for being a baker during an epoch
                        let reward = baker_rewards.get(&traced_account);
                        if let Some(reward) = reward {
                            println!("Time: {} Baking Reward: {}", pretty_time(timestamp), reward)
                        }
                    }
                    SpecialTransactionOutcome::Mint { .. } => {
                        // This does not affect a specific account directly.
                    }
                    SpecialTransactionOutcome::FinalizationRewards {
                        finalization_rewards,
                        ..
                    } => {
                        let reward = finalization_rewards.get(&traced_account);
                        if let Some(reward) = reward {
                            println!(
                                "Time: {} Finalization Reward: {}",
                                pretty_time(timestamp),
                                reward
                            )
                        }
                    }
                    SpecialTransactionOutcome::BlockReward { baker_reward, .. } => {
                        // The reward for baking a concrete block
                        println!(
                            "Time: {} Baker Reward: {}",
                            pretty_time(timestamp),
                            baker_reward
                        )
                    }
                }
            }
        }
    })
    .await;
}

fn pretty_time(timestamp: Timestamp) -> String {
    let naive = NaiveDateTime::from_timestamp(timestamp.millis as i64, 0);
    let dt: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    dt.format("UTC %Y-%m-%d %H:%M:%S").to_string()
}
