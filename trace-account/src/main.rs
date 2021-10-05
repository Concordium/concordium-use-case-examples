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
use csv;
use futures::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    error::Error,
    fmt::Debug,
    fs::File,
    io::{self, BufReader},
    path::*,
};
use structopt::StructOpt;
use tokio_postgres::NoTls;

#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
struct CsvRow {
    timestamp:               Timestamp,
    transaction_type:        String,
    sender:                  Option<AccountAddress>, /* todo should we be able to handle
                                                      * contract addresses? */
    receiver:                Option<AccountAddress>,
    cost:                    Option<Amount>,
    reward:                  Option<Amount>, // could be included in a net added to or net total
    added_to_traced_account: Option<AmountDelta>, /* net effects of all amounts moved on the account
                                              * being traced, not including cost */
    total:                   AmountDelta,
}

async fn trace_single_account(
    table: &elgamal::BabyStepGiantStep<id::constants::ArCurve>,
    db: &DatabaseClient,
    input: &RetrievalInput,
    writer: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let csv_writer = csv::Writer::from_writer(writer); // todo move up
    let traced_account = input.account_address;

    let rows = db
        .query_account(&traced_account, 10000, QueryOrder::Ascending {
            start: None,
        })
        .await?; // todo which limit should be used?
    println!("Tracing: {}.", traced_account);
    rows.fold(Ok(csv_writer), |writer, entry| async {
        let mut wtr = writer?;
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
                        match &at.effects {
                            AccountTransactionEffects::None {
                                transaction_type, ..
                            } => match transaction_type {
                                None => {
                                    let output = CsvRow {
                                        timestamp,
                                        transaction_type: "Unknown".to_string(),
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        added_to_traced_account: None,
                                        total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                    };
                                    wtr.serialize(output)?;
                                }
                                Some(transaction_type) => {
                                    let output = CsvRow {
                                        timestamp,
                                        transaction_type: serde_json::to_string(&transaction_type)?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        added_to_traced_account: None,
                                        total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                    };
                                    wtr.serialize(&output)?;
                                }
                            },
                            AccountTransactionEffects::ModuleDeployed { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::ContractInitialized { data } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: Some(AmountDelta::NegativeAmount(
                                        data.amount,
                                    )),
                                    total: AmountDelta::NegativeAmount(Amount {
                                        microgtu: at.cost.microgtu + data.amount.microgtu,
                                    }),
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::ContractUpdateIssued { effects } => {
                                let mut added_to_account = 0_u64;
                                let mut taken_from_account = 0_u64;
                                for eff in effects {
                                    match eff {
                                        ContractTraceElement::Updated { data } => {
                                            // If effect required money from an account
                                            if let Address::Account(instigator) = data.instigator {
                                                // If the account is the account being traced
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
                                            // If effect sent money to an account
                                            if to == &traced_account {
                                                // If the account is the account being traced
                                                added_to_account += amount.microgtu;
                                            }
                                        }
                                    }
                                }
                                let (net, total) = if taken_from_account > added_to_account {
                                    // Money was taken from traced account net and total
                                    (
                                        AmountDelta::NegativeAmount(Amount::from(
                                            taken_from_account - added_to_account,
                                        )),
                                        (AmountDelta::NegativeAmount(Amount::from(
                                            (taken_from_account - added_to_account)
                                                + at.cost.microgtu,
                                        ))),
                                    )
                                } else {
                                    (
                                        AmountDelta::PositiveAmount(Amount::from(
                                            added_to_account - taken_from_account,
                                        )),
                                        (if at.cost.microgtu > added_to_account - taken_from_account
                                        {
                                            // Cost exceeds net amount sent to traced account
                                            AmountDelta::NegativeAmount(Amount {
                                                microgtu: at.cost.microgtu
                                                    - (added_to_account - taken_from_account),
                                            })
                                        } else {
                                            AmountDelta::PositiveAmount(Amount {
                                                microgtu: (added_to_account
                                                    - taken_from_account
                                                    - at.cost.microgtu),
                                            })
                                        }),
                                    )
                                };
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: Some(net),
                                    total,
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::AccountTransfer { amount, to } => {
                                let (net, total) = if sender == traced_account {
                                    (
                                        AmountDelta::NegativeAmount(*amount),
                                        AmountDelta::NegativeAmount(Amount {
                                            microgtu: amount.microgtu + at.cost.microgtu,
                                        }),
                                    )
                                } else {
                                    (
                                        AmountDelta::PositiveAmount(*amount),
                                        AmountDelta::PositiveAmount(*amount),
                                    )
                                };
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: Some(*to),
                                    cost,
                                    reward: None,
                                    added_to_traced_account: Some(net),
                                    total,
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::AccountTransferWithMemo {
                                amount,
                                to,
                                ..
                            } => {
                                let (net, total) = if sender == traced_account {
                                    (
                                        AmountDelta::NegativeAmount(*amount),
                                        AmountDelta::NegativeAmount(Amount {
                                            microgtu: amount.microgtu + at.cost.microgtu,
                                        }),
                                    )
                                } else {
                                    (
                                        AmountDelta::PositiveAmount(*amount),
                                        AmountDelta::PositiveAmount(*amount),
                                    )
                                };
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: Some(*to),
                                    cost,
                                    reward: None,
                                    added_to_traced_account: Some(net),
                                    total,
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::BakerAdded { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::BakerRemoved { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::BakerStakeUpdated { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::BakerRestakeEarningsUpdated { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::BakerKeysUpdated { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
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
                                    let output = CsvRow {
                                        timestamp,
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(receiver),
                                        cost,
                                        reward: None,
                                        added_to_traced_account: Some(delta),
                                        total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        }, // todo fix total
                                    };
                                    wtr.serialize(&output)?;
                                } else {
                                    let output = CsvRow {
                                        timestamp,
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(receiver),
                                        cost,
                                        reward: None,
                                        added_to_traced_account: None,
                                        total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                    };
                                    wtr.serialize(&output)?;
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
                                    let output = CsvRow {
                                        timestamp,
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(receiver),
                                        cost,
                                        reward: None,
                                        added_to_traced_account: Some(delta),
                                        total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        }, // todo fix total
                                    };
                                    wtr.serialize(&output)?;
                                } else {
                                    let output = CsvRow {
                                        timestamp,
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(receiver),
                                        cost,
                                        reward: None,
                                        added_to_traced_account: None,
                                        total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                    };
                                    wtr.serialize(&output)?;
                                }
                            }
                            AccountTransactionEffects::TransferredToEncrypted { data } => {
                                // todo Should I put a decrease in total (and amounts), since this
                                // much less money is now in the
                                // public balance?
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::TransferredToPublic { amount, .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                                // todo should I put an increase in total (and
                                // amounts), since this much extra money is
                                // now in the public balance?
                            }
                            AccountTransactionEffects::TransferredWithSchedule { to, amount } => {
                                let mut combined_amount = 0;
                                for (_, am) in amount {
                                    combined_amount += am.microgtu;
                                }
                                let (net_amount, total) = if sender == traced_account {
                                    // Traced account pays all scheduled amounts + the cost
                                    (
                                        AmountDelta::NegativeAmount(Amount::from(combined_amount)),
                                        AmountDelta::NegativeAmount(Amount::from(
                                            combined_amount + at.cost.microgtu,
                                        )),
                                    )
                                } else {
                                    // Traced account gets all scheduled amounts
                                    (
                                        AmountDelta::PositiveAmount(Amount::from(combined_amount)),
                                        AmountDelta::PositiveAmount(Amount::from(combined_amount)),
                                    )
                                };
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: Some(*to),
                                    cost,
                                    reward: None,
                                    added_to_traced_account: Some(net_amount),
                                    total,
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::TransferredWithScheduleAndMemo {
                                to,
                                amount,
                                ..
                            } => {
                                let mut combined_amount = 0;
                                for (_, am) in amount {
                                    combined_amount += am.microgtu;
                                }
                                let (net_amount, total) = if sender == traced_account {
                                    // Traced account pays all scheduled amounts + the cost
                                    (
                                        AmountDelta::NegativeAmount(Amount::from(combined_amount)),
                                        AmountDelta::NegativeAmount(Amount::from(
                                            combined_amount + at.cost.microgtu,
                                        )),
                                    )
                                } else {
                                    (
                                        AmountDelta::PositiveAmount(Amount::from(combined_amount)),
                                        AmountDelta::PositiveAmount(Amount::from(combined_amount)),
                                    )
                                };
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: Some(*to),
                                    cost,
                                    reward: None,
                                    added_to_traced_account: Some(net_amount),
                                    total,
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::CredentialKeysUpdated { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::CredentialsUpdated { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                            AccountTransactionEffects::DataRegistered { .. } => {
                                let output = CsvRow {
                                    timestamp,
                                    transaction_type: serde_json::to_string(
                                        &at.effects.transaction_type(),
                                    )?,
                                    sender: Some(sender),
                                    receiver: None,
                                    cost,
                                    reward: None,
                                    added_to_traced_account: None,
                                    total: if let Some(cost) = cost {
                                        AmountDelta::NegativeAmount(cost)
                                    } else {
                                        AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                    },
                                };
                                wtr.serialize(&output)?;
                            }
                        }
                    }
                    BlockItemSummaryDetails::AccountCreation(_) => {
                        // This has no associated costs
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
                        if let Some(&reward) = reward {
                            let output = CsvRow {
                                timestamp,
                                transaction_type: "BakerReward".to_string(),
                                sender: None,
                                receiver: Some(traced_account),
                                cost: None,
                                reward: Some(reward),
                                added_to_traced_account: None,
                                total: AmountDelta::PositiveAmount(reward),
                            };
                            wtr.serialize(output)?;
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
                        if let Some(&reward) = reward {
                            let output = CsvRow {
                                timestamp,
                                transaction_type: "FinalizationReward".to_string(),
                                sender: None,
                                receiver: Some(traced_account),
                                cost: None,
                                reward: Some(reward),
                                added_to_traced_account: None,
                                total: AmountDelta::PositiveAmount(reward),
                            };
                            wtr.serialize(output)?;
                        }
                    }
                    SpecialTransactionOutcome::BlockReward { baker_reward, .. } => {
                        // The reward for baking a block
                        let output = CsvRow {
                            timestamp,
                            transaction_type: "BlockReward".to_string(),
                            sender: None,
                            receiver: Some(traced_account),
                            cost: None,
                            reward: Some(baker_reward),
                            added_to_traced_account: None,
                            total: AmountDelta::PositiveAmount(baker_reward),
                        };
                        wtr.serialize(output)?;
                    }
                }
            }
        }
        Ok::<_, std::io::Error>(wtr) // Explicit error type allows use of ?
    })
    .await?;

    Ok(())
}

fn pretty_time(timestamp: Timestamp) -> String {
    let naive = NaiveDateTime::from_timestamp(timestamp.millis as i64, 0);
    let dt: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    dt.format("UTC %Y-%m-%d %H:%M:%S").to_string()
}
