use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common,
    endpoints::{Client, Endpoint},
    id, postgres,
    types::{self, smart_contracts, transactions},
};
use futures::stream::StreamExt;
use serde::*;
use std::{
    convert::{Infallible, TryFrom},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use structopt::*;
use thiserror::*;
use tokio::sync::mpsc;
use warp::{body::BodyDeserializeError, hyper::StatusCode, reject::InvalidQuery, Filter};

pub static FORM: &str = include_str!("../data/send.html");

#[derive(Serialize, Deserialize)]
#[serde(rename = "camelCase")]
/// A helper type to parse the submitted form. Serde serialization is how values
/// of this type are constructed.
struct Form {
    /// The memo, encoded in hex.
    memo:   smart_contracts::Parameter,
    /// The address of the contract to send to. Subindex is always 0 in the
    /// current protocol.
    index:  types::ContractIndex,
    /// The amount to send. Note that this is parsed as microGTU.
    amount: common::types::Amount,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "camelCase")]
/// A helper struct to parse the query parameters to the `observe` endpoint.
struct ContractQuery {
    #[serde(default)]
    index:    types::ContractIndex,
    #[serde(default)]
    subindex: types::ContractSubIndex,
    #[serde(default)]
    /// Only include transactions that are sends with memos.
    filter:   bool,
}

#[derive(StructOpt)]
/// Structure to hold command-line arguments.
struct App {
    #[structopt(
        long = "listen-addr",
        help = "Address the server will listen on.",
        default_value = "0.0.0.0:3000"
    )]
    listen_addr:   SocketAddr,
    #[structopt(
        long = "redirect-base",
        help = "Base URL on which the server is listening.",
        default_value = "http://localhost:3000"
    )]
    redirect_base: url::Url,
    #[structopt(long = "account", help = "Account that will send transactions.")]
    account:       PathBuf,
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint:      Endpoint,
    #[structopt(
        long = "db",
        default_value = "host=localhost dbname=transaction-outcome user=postgres \
                         password=password port=5432",
        help = "Database connection string."
    )]
    config:        postgres::Config,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Helper to parse account keys.
struct AccountData {
    account_keys: id::types::AccountKeys,
    address:      id::types::AccountAddress,
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

    // Initialize the logger so that we get some information when request are made.
    env_logger::init();

    let keys: AccountData = serde_json::from_str(
        &std::fs::read_to_string(app.account).context("Could not read the keys file.")?,
    )
    .context("Could not parse the accounts file.")?;

    // The GRPC client
    let mut client = Client::connect(app.endpoint, "rpcadmin".to_string()).await?;

    // Establish baseline parameters. We get the next available nonce for the
    // account and fail if there are non-finalized transactions for the account.
    // This is for simplicity. We could add recovery and more error handling
    // here.
    let nonce_response = client.get_next_account_nonce(&keys.address).await?;
    anyhow::ensure!(
        nonce_response.all_final,
        "There are unfinalized transactions. Refusing to start."
    );

    // The channel to communicate between the worker that sends transactions and the
    // `submit` handler. The handler tries to enqueue the parameters for the for
    // 500ms in this bounded queue.
    let (sender, mut receiver) = mpsc::channel(50); // allocate a channel for 50 pending transactions.

    // The task, which is scheduled in the background, that waits for messages on
    // the channel we just created and sends transactions to the node.
    let sender_task = async move {
        let mut nonce = nonce_response.nonce;
        while let Some((amount, message, address)) = receiver.recv().await {
            let expiry = common::types::TransactionTime::from_seconds(
                (chrono::Utc::now().timestamp() + 300) as u64,
            );
            let payload = transactions::Payload::Update {
                payload: transactions::UpdateContractPayload {
                    amount,
                    address,
                    receive_name: smart_contracts::ReceiveName::try_from(
                        "memo.receive".to_string(),
                    )
                    .unwrap(),
                    message,
                },
            };
            let energy = transactions::send::GivenEnergy::Add(700.into());
            let tx = transactions::send::make_and_sign_transaction(
                &keys.account_keys,
                keys.address,
                nonce,
                expiry,
                energy,
                payload,
            );
            let bi = transactions::BlockItem::AccountTransaction(tx);

            if let Ok(hash) = client.send_block_item(&bi).await {
                nonce.next_mut();
                log::info!("Transaction submitted. Its hash is {}", hash);
            } else {
                log::error!("Could not submit transaction.");
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    // Spawn a background task that will send transactions that are enqueued.
    // We never shut down the background task so the handle is not used. But if the
    // server supported some orderly shutdown we would use it.
    let _handle = tokio::spawn(sender_task);

    // Handler that serves as a dummy wallet, where users can send transfers to
    // smart contracts.
    let wallet_handler = warp::path("wallet").and(
        warp::get()
            .map(move || warp::reply::html(FORM))
            .with(warp::log("send")),
    );

    // This closure is used to construct the redirect links from after a POST to the
    // `submit` endpoint. It construct the URL with query parameters that make
    // the `observe` endpoint query the contract to which the user sent a transfer.
    let redirect_base = app.redirect_base;
    let redirect_url = move |addr: types::ContractAddress| {
        let mut new = redirect_base.clone();
        new.set_path("observe");
        let query = format!("index={}&subindex={}", addr.index, addr.subindex);
        new.set_query(Some(&query));
        async move {
            let reply = warp::reply::reply();
            let reply = warp::reply::with_status(reply, StatusCode::SEE_OTHER);
            let reply = warp::reply::with_header(reply, "location", new.to_string());
            Ok::<_, warp::reject::Rejection>(reply)
        }
    };

    // Handler for form submission.
    // This checks that the parameter to the contract is of the correct shape (i.e.,
    // 32 bytes), but no more.
    let form_handler = warp::path("submit")
        .and(warp::body::content_length_limit(1024 * 32))
        .and(
            warp::post()
                .and(warp::body::form())
                .and_then(move |form: Form| enqueue_transaction(form, sender.clone()))
                .and_then(redirect_url)
                .with(warp::log("submit")),
        );

    // The postgres database client Arc. The client is not cloneable, by design,
    // so we put it behind an Arc.
    let db = Arc::new(postgres::DatabaseClient::create(app.config, postgres::NoTls).await?);

    // Endpoint to show transactions affecting the given smart contract.
    let contract_shower = warp::path("observe").and(
        warp::get()
            .and(warp::query())
            .and_then(move |query: ContractQuery| {
                list_transactions(
                    db.clone(),
                    types::ContractAddress::new(query.index, query.subindex),
                    query.filter,
                )
            })
            .with(warp::log("observe")),
    );

    let server = wallet_handler
        .or(form_handler)
        .or(contract_shower)
        .recover(handle_rejection);

    warp::serve(server).run(app.listen_addr).await;

    Ok(())
}

/// List transactions for the given smart contract.
/// If `filter` is set to `true` then this will do some processing of the
/// results so that only smart contract updates are returned, and those in a
/// condensed format.
async fn list_transactions(
    db: Arc<postgres::DatabaseClient>,
    contract: types::ContractAddress,
    filter: bool,
) -> Result<warp::reply::Json, warp::reject::Rejection> {
    log::info!("Querying contract {:?}", contract);
    let query = db
        .query_contract(contract, 20, postgres::QueryOrder::Descending {
            start: None,
        })
        .await
        .map_err(Errors::DBError)?;
    if filter {
        let rows =
            query.filter_map(|row| async move {
                match row.summary {
                    postgres::DatabaseSummaryEntry::BlockItem(types::BlockItemSummary {
                        index: _,
                        energy_cost: _,
                        hash,
                        details:
                            types::BlockItemSummaryDetails::AccountTransaction(
                                types::AccountTransactionDetails {
                                    cost: _,
                                    sender,
                                    effects:
                                        types::AccountTransactionEffects::ContractUpdateIssued {
                                            effects,
                                        },
                                },
                            ),
                    }) => {
                        let events = effects
                            .into_iter()
                            .filter_map(|event| match event {
                                types::ContractTraceElement::Updated { data } => {
                                    if <&str as From<_>>::from(&data.receive_name) == "memo.receive"
                                    {
                                        Some(serde_json::json!({
                                            "sender": sender,
                                            "memo": data.message,
                                            "amount": data.amount,
                                            "transactionHash": hash
                                        }))
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>();
                        Some(events)
                    }
                    _ => None,
                }
            });
        let rows = rows.collect::<Vec<_>>().await;
        Ok(warp::reply::json(&rows))
    } else {
        let rows = query.map(|x| x.summary).collect::<Vec<_>>().await;
        Ok(warp::reply::json(&rows))
    }
}

type ChannelValues = (
    common::types::Amount,
    smart_contracts::Parameter,
    types::ContractAddress,
);

/// Attempt to enqueue a transaction (actually, parameters to a transaction) to
/// the queue. If parameters cannot be enqueued in 500ms then reject the request
/// with an appropriate error.
async fn enqueue_transaction(
    form: Form,
    sender: mpsc::Sender<ChannelValues>,
) -> Result<types::ContractAddress, warp::reject::Rejection> {
    let addr = types::ContractAddress::new(form.index, 0.into());
    if form.memo.as_ref().len() != 32 {
        return Err(Errors::InvalidParameterLength.into());
    }
    sender
        .send_timeout(
            (form.amount, form.memo, addr),
            std::time::Duration::from_millis(500),
        )
        .await
        .map_err(Errors::SendError)?;
    Ok(addr)
}

#[derive(Debug, Error)]
/// Custom errors that can occur during request processing (in addition to
/// failure to parse parameters, etc., which are handled by `warp` already.
enum Errors {
    #[error("Error enqueuing transaction: {0}")]
    SendError(#[from] mpsc::error::SendTimeoutError<ChannelValues>),
    #[error("Error enqueuing transaction: {0}")]
    DBError(#[from] postgres::Error),
    #[error("Parameter must be exactly 32 bytes long")]
    InvalidParameterLength,
}

impl warp::reject::Reject for Errors {}

/// Helper function to make the error reply. All error responses will have a
/// json body with code and error.
fn mk_reply(message: &str, code: StatusCode) -> impl warp::Reply {
    let msg = serde_json::json!({
        "error": message,
        "code": code.as_u16(),
    });
    warp::reply::with_status(warp::reply::json(&msg), code)
}

/// Handler to transform failures into a consistent response with a JSON body
/// and a short description of the failure.
async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
    if err.is_not_found() {
        let code = StatusCode::NOT_FOUND;
        Ok(mk_reply("Not found.", code))
    } else if let Some(errors) = err.find::<Errors>() {
        match errors {
            Errors::SendError(send_error) => match send_error {
                mpsc::error::SendTimeoutError::Timeout(values) => {
                    log::error!("Transaction queue full: {:?}", values);
                    let message = "Could not send transaction due to high load.";
                    let code = StatusCode::TOO_MANY_REQUESTS;
                    Ok(mk_reply(message, code))
                }
                mpsc::error::SendTimeoutError::Closed(values) => {
                    log::error!("Error enqueueing transaction {:?}", values);
                    let message = "Server crashed..";
                    let code = StatusCode::INTERNAL_SERVER_ERROR;
                    Ok(mk_reply(message, code))
                }
            },
            Errors::DBError(err) => {
                log::error!("Database access error: {}", err);
                let message = "Database access error.";
                let code = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(mk_reply(message, code))
            }
            Errors::InvalidParameterLength => {
                let message = "The memo must be exactly 32 bytes long, and encoded in hex.";
                let code = StatusCode::BAD_REQUEST;
                Ok(mk_reply(message, code))
            }
        }
    } else if let Some(error) = err.find::<BodyDeserializeError>() {
        let message = format!("{}", error);
        let code = StatusCode::BAD_REQUEST;
        Ok(mk_reply(&message, code))
    } else if let Some(error) = err.find::<InvalidQuery>() {
        let message = format!("Invalid query parameters: {}", error);
        let code = StatusCode::BAD_REQUEST;
        Ok(mk_reply(&message, code))
    } else {
        let code = StatusCode::BAD_REQUEST;
        let message = "Bad request.";
        Ok(mk_reply(message, code))
    }
}
