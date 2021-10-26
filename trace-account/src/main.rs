use anyhow::Context;
use chrono::{DateTime, NaiveDateTime, Utc};
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{types::*, *},
    elgamal, encrypted_transfers, endpoints, id,
    id::types::*,
    postgres::{DatabaseClient, QueryOrder, *},
    types::*,
};
use futures::*;
use serde::{de::DeserializeOwned, Serialize, Serializer};
use std::{
    fmt::Debug,
    fs::File,
    io::{self, BufReader},
    path::*,
};
use structopt::StructOpt;
use tokio_postgres::NoTls;

#[derive(Debug, Clone, Copy)]
pub enum AmountDelta {
    PositiveAmount(Amount),
    NegativeAmount(Amount),
}

impl Serialize for AmountDelta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        match self {
            AmountDelta::PositiveAmount(am) => serializer.serialize_i64(am.microgtu as i64),
            AmountDelta::NegativeAmount(am) => serializer.serialize_i64(-(am.microgtu as i64)),
        }
    }
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
    // Optional field does not match output of AR tool, but allows easy querying with only an
    // account address.
    reg_id:                Option<CredentialRegistrationID>,
    /// The address output by AR tool is the one derived directly from the reg
    /// ID, this might not be the actual address of the account.
    /// It should not be used for queriyng if reg ID is present.
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
    global:   PathBuf,
    #[structopt(
        long = "db",
        default_value = "host=localhost dbname=transaction-outcome user=postgres \
                         password=password port=5432",
        help = "Database connection string."
    )]
    config:   tokio_postgres::Config,
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint: tonic::transport::Endpoint,
    #[structopt(subcommand)]
    mode:     Mode,
}

#[tokio::main(flavor = "multi_thread")]
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
        Err(e) => panic!("Connecting to database failed: {}", e),
    };
    let client = match endpoints::Client::connect(tr.endpoint, "rpcadmin".to_string()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Connecting to grpc failed: {}", e);
            return;
        }
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
            let futures = inputs
                .iter()
                .map(|input| trace_single_account(&table, &db, &client, input));
            future::join_all(futures).await;
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
                        reg_id: None,
                        account_address: address,
                        encryption_secret_key,
                    }
                }
                None => RetrievalInput {
                    reg_id:                None,
                    account_address:       address,
                    encryption_secret_key: None,
                },
            };
            match trace_single_account(&table, &db, &client, &input).await {
                Ok(()) => (),
                Err(e) => panic!("Tracing failed: {}", e),
            }
        }
    };
}

#[derive(Debug, Serialize)]
struct CsvRow {
    time:             String,
    transaction_type: String,
    sender:           Option<AccountAddress>,
    receiver:         Option<AccountAddress>,
    cost:             Option<Amount>,
    reward:           Option<Amount>,
    summed_transfers: Option<AmountDelta>,
    // summed_transfers + reward - cost
    public_total:     AmountDelta,
    // amount added or removed from encrypted funds, when changed
    encrypted_total:  Option<AmountDelta>,
}

async fn trace_single_account(
    table: &elgamal::BabyStepGiantStep<id::constants::ArCurve>,
    db: &DatabaseClient,
    client: &concordium_rust_sdk::endpoints::Client,
    input: &RetrievalInput,
) -> anyhow::Result<()> {
    let traced_account = match &input.reg_id {
        None => input.account_address,
        Some(reg_id) => {
            let mut client = client.clone();
            let consensus_info = client.get_consensus_status().await?;
            let acc_info = client
                .get_account_info_by_cred_id(reg_id, &consensus_info.best_block)
                .await?;
            match acc_info
                .account_credentials
                .get(&CredentialIndex { index: 0 })
            {
                None => panic!("Initial credential missing."), // Initial credential is always
                // present.
                Some(versioned_credential) => match &versioned_credential.value {
                    concordium_rust_sdk::id::types::AccountCredentialWithoutProofs::Initial {
                        icdv,
                    } => {
                        let init_reg_id = icdv.reg_id;
                        AccountAddress::new(&init_reg_id)
                    }
                    concordium_rust_sdk::id::types::AccountCredentialWithoutProofs::Normal {
                        cdv,
                        ..
                    } => {
                        let init_reg_id = cdv.cred_id;
                        AccountAddress::new(&init_reg_id)
                    }
                },
            }
        }
    };
    let mut file = Path::new(&traced_account.to_string()).to_path_buf();
    file.set_extension("csv");
    let mut writer =
        csv::Writer::from_writer(std::fs::File::create(file).expect("Cannot create output file"));
    let rows = db
        .query_account(&traced_account, 10000, QueryOrder::Ascending {
            start: None,
        })
        .await?; // todo which limit should be used?
    println!("Tracing: {}.", traced_account);
    writer = rows
        .fold(Ok(writer), |writer, entry| async {
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
                            let get_encrypted_transfer_delta =
                                |added: &NewEncryptedAmountEvent,
                                 removed: &EncryptedAmountRemovedEvent|
                                 -> Option<AmountDelta> {
                                    if let Some(key) = &input.encryption_secret_key {
                                        if sender == traced_account {
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
                                            Some(AmountDelta::NegativeAmount(Amount::from(
                                                before.microgtu - after.microgtu,
                                            )))
                                        } else {
                                            let amount_received =
                                                encrypted_transfers::decrypt_amount(
                                                    table,
                                                    key,
                                                    &added.encrypted_amount,
                                                );
                                            Some(AmountDelta::PositiveAmount(amount_received))
                                        }
                                    } else {
                                        None
                                    }
                                };
                            let get_transfer_sum_and_total = |receiver: &AccountAddress,
                                                              amount: &Amount|
                             -> (
                                Option<AmountDelta>,
                                AmountDelta,
                            ) {
                                if sender == traced_account {
                                    if *receiver == sender {
                                        // in case the traced account sent a transfer to its own
                                        // address.
                                        (None, AmountDelta::NegativeAmount(at.cost))
                                    } else {
                                        (
                                            Some(AmountDelta::NegativeAmount(*amount)),
                                            AmountDelta::NegativeAmount(Amount {
                                                microgtu: amount.microgtu + at.cost.microgtu,
                                            }),
                                        )
                                    }
                                } else {
                                    (
                                        Some(AmountDelta::PositiveAmount(*amount)),
                                        AmountDelta::PositiveAmount(*amount),
                                    )
                                }
                            };
                            match &at.effects {
                                AccountTransactionEffects::None {
                                    transaction_type, ..
                                } => match transaction_type {
                                    None => {
                                        let output = CsvRow {
                                            time: pretty_time(timestamp),
                                            transaction_type: "Unknown".to_string(),
                                            sender: Some(sender),
                                            receiver: None,
                                            cost,
                                            reward: None,
                                            summed_transfers: None,
                                            public_total: if let Some(cost) = cost {
                                                AmountDelta::NegativeAmount(cost)
                                            } else {
                                                AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                            },
                                            encrypted_total: None,
                                        };
                                        wtr.serialize(output)?;
                                    }
                                    Some(transaction_type) => {
                                        let output = CsvRow {
                                            time: pretty_time(timestamp),
                                            transaction_type: serde_json::to_string(
                                                &transaction_type,
                                            )?,
                                            sender: Some(sender),
                                            receiver: None,
                                            cost,
                                            reward: None,
                                            summed_transfers: None,
                                            public_total: if let Some(cost) = cost {
                                                AmountDelta::NegativeAmount(cost)
                                            } else {
                                                AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                            },
                                            encrypted_total: None,
                                        };
                                        wtr.serialize(&output)?;
                                    }
                                },
                                AccountTransactionEffects::ModuleDeployed { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::ContractInitialized { data } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: Some(AmountDelta::NegativeAmount(
                                            data.amount,
                                        )),
                                        public_total: AmountDelta::NegativeAmount(Amount {
                                            microgtu: at.cost.microgtu + data.amount.microgtu,
                                        }),
                                        encrypted_total: None,
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
                                                if let Address::Account(instigator) =
                                                    data.instigator
                                                {
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
                                    let (net, public_total) = if taken_from_account
                                        > added_to_account
                                    {
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
                                            (if at.cost.microgtu
                                                > added_to_account - taken_from_account
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
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: Some(net),
                                        public_total,
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::AccountTransfer { amount, to } => {
                                    let (transfer_sum, public_total) =
                                        get_transfer_sum_and_total(to, amount);
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(*to),
                                        cost,
                                        reward: None,
                                        summed_transfers: transfer_sum,
                                        public_total,
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::AccountTransferWithMemo {
                                    amount,
                                    to,
                                    ..
                                } => {
                                    let (transfer_sum, public_total) =
                                        get_transfer_sum_and_total(to, amount);
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(*to),
                                        cost,
                                        reward: None,
                                        summed_transfers: transfer_sum,
                                        public_total,
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::BakerAdded { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::BakerRemoved { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::BakerStakeUpdated { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::BakerRestakeEarningsUpdated {
                                    ..
                                } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::BakerKeysUpdated { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::EncryptedAmountTransferred {
                                    removed,
                                    added,
                                } => {
                                    let receiver = added.receiver;
                                    let delta = get_encrypted_transfer_delta(added, removed);
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(receiver),
                                        cost,
                                        reward: None,
                                        summed_transfers: delta,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: delta,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::EncryptedAmountTransferredWithMemo {
                                    added,
                                    removed,
                                    ..
                                } => {
                                    let receiver = added.receiver;
                                    let delta = get_encrypted_transfer_delta(added, removed);
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(receiver),
                                        cost,
                                        reward: None,
                                        summed_transfers: delta,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: delta,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::TransferredToEncrypted { data } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: AmountDelta::NegativeAmount(Amount {
                                            microgtu: at.cost.microgtu + data.amount.microgtu,
                                        }),
                                        encrypted_total: Some(AmountDelta::PositiveAmount(
                                            data.amount,
                                        )),
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::TransferredToPublic {
                                    amount, ..
                                } => {
                                    let public_total_increase =
                                        if amount.microgtu >= at.cost.microgtu {
                                            AmountDelta::PositiveAmount(Amount {
                                                microgtu: amount.microgtu - at.cost.microgtu,
                                            })
                                        } else {
                                            AmountDelta::NegativeAmount(Amount {
                                                microgtu: at.cost.microgtu - amount.microgtu,
                                            })
                                        };
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: public_total_increase,
                                        encrypted_total: Some(AmountDelta::NegativeAmount(*amount)),
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::TransferredWithSchedule {
                                    to,
                                    amount,
                                } => {
                                    let mut combined_amount = 0;
                                    for (_, am) in amount {
                                        combined_amount += am.microgtu;
                                    }
                                    let (transfer_sum, total) =
                                        get_transfer_sum_and_total(to, &Amount {
                                            microgtu: combined_amount,
                                        });
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(*to),
                                        cost,
                                        reward: None,
                                        summed_transfers: transfer_sum,
                                        public_total: total,
                                        encrypted_total: None,
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
                                    let (transfer_sum, total) =
                                        get_transfer_sum_and_total(to, &Amount {
                                            microgtu: combined_amount,
                                        });
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: Some(*to),
                                        cost,
                                        reward: None,
                                        summed_transfers: transfer_sum,
                                        public_total: total,
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::CredentialKeysUpdated { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::CredentialsUpdated { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                                AccountTransactionEffects::DataRegistered { .. } => {
                                    let output = CsvRow {
                                        time: pretty_time(timestamp),
                                        transaction_type: serde_json::to_string(
                                            &at.effects.transaction_type(),
                                        )?,
                                        sender: Some(sender),
                                        receiver: None,
                                        cost,
                                        reward: None,
                                        summed_transfers: None,
                                        public_total: if let Some(cost) = cost {
                                            AmountDelta::NegativeAmount(cost)
                                        } else {
                                            AmountDelta::PositiveAmount(Amount { microgtu: 0 })
                                        },
                                        encrypted_total: None,
                                    };
                                    wtr.serialize(&output)?;
                                }
                            }
                        }
                        BlockItemSummaryDetails::AccountCreation(_) => {
                            // This has no associated costs
                        }
                        BlockItemSummaryDetails::Update(_) => {
                            // A protocol update is a free transaction, it does
                            // not affect any
                            // accounts directly.
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
                                    time:             pretty_time(timestamp),
                                    transaction_type: "BakerReward".to_string(),
                                    sender:           None,
                                    receiver:         Some(traced_account),
                                    cost:             None,
                                    reward:           Some(reward),
                                    summed_transfers: None,
                                    public_total:     AmountDelta::PositiveAmount(reward),
                                    encrypted_total:  None,
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
                                    time:             pretty_time(timestamp),
                                    transaction_type: "FinalizationReward".to_string(),
                                    sender:           None,
                                    receiver:         Some(traced_account),
                                    cost:             None,
                                    reward:           Some(reward),
                                    summed_transfers: None,
                                    public_total:     AmountDelta::PositiveAmount(reward),
                                    encrypted_total:  None,
                                };
                                wtr.serialize(output)?;
                            }
                        }
                        SpecialTransactionOutcome::BlockReward { baker_reward, .. } => {
                            // The reward for baking a block
                            let output = CsvRow {
                                time:             pretty_time(timestamp),
                                transaction_type: "BlockReward".to_string(),
                                sender:           None,
                                receiver:         Some(traced_account),
                                cost:             None,
                                reward:           Some(baker_reward),
                                summed_transfers: None,
                                public_total:     AmountDelta::PositiveAmount(baker_reward),
                                encrypted_total:  None,
                            };
                            wtr.serialize(output)?;
                        }
                    }
                }
            }
            Ok::<_, std::io::Error>(wtr) // Explicit error type allows use of
                                         // `?`
        })
        .await?;
    writer.flush()?;
    Ok(())
}

fn pretty_time(timestamp: Timestamp) -> String {
    let naive = NaiveDateTime::from_timestamp(timestamp.millis as i64 / 1000, 0); // todo display subsecond part?
    let dt: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    dt.format("UTC %Y-%m-%d %H:%M:%S").to_string()
}
