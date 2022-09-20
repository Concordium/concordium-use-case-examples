use concordium_rust_sdk::{
    endpoints::{QueryError, RPCError},
    id::{
        constants::{ArCurve, AttributeKind},
        id_verifier::verify_attribute_range,
        range_proof::RangeProof,
        types::{AccountAddress, AccountCredentialWithoutProofs, AttributeTag, GlobalContext},
    },
};

use log::{error, info, warn};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;

use warp::{http::StatusCode, Filter, Rejection, Reply};

/// Structure used to receive the correct command line arguments.
#[derive(Debug, StructOpt)]
struct WebShopConfig {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint: concordium_rust_sdk::endpoints::Endpoint,
    #[structopt(
        long = "port",
        default_value = "8100",
        help = "Port on which the server will listen on."
    )]
    port:     u16,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AgeProofOutput {
    account: AccountAddress,
    lower:   AttributeKind,
    upper:   AttributeKind,
    proof:   RangeProof<ArCurve>,
}

#[derive(
    Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize,
)]
enum Item {
    Alpha,
    Beta,
    Gamma,
    Xi,
    Zeta,
    Omega,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(transparent)]
struct Basket {
    basket: Vec<Item>,
}

struct Server {
    basket:         Basket,
    global_context: GlobalContext<ArCurve>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let app = WebShopConfig::clap()
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .global_setting(clap::AppSettings::ColoredHelp);
    let matches = app.get_matches();
    let app: WebShopConfig = WebShopConfig::from_clap(&matches);
    let mut client =
        concordium_rust_sdk::endpoints::Client::connect(app.endpoint, "rpcadmin").await?;
    let consensus_info = client.get_consensus_status().await?;
    let global_context = client
        .get_cryptographic_parameters(&consensus_info.last_finalized_block)
        .await?;
    let state = Arc::new(Mutex::new(Server {
        basket: Basket { basket: Vec::new() },
        global_context,
    }));

    let add_to_basket = warp::post()
        .and(warp::filters::body::content_length_limit(50 * 1024))
        .and(warp::path!("add"))
        .and(handle_add_basket(client, state));

    let list_items = warp::get().and(warp::path!("list")).and_then(|| async {
        Ok::<_, Rejection>(warp::reply::json(&[
            Item::Alpha,
            Item::Beta,
            Item::Gamma,
            Item::Xi,
            Item::Zeta,
            Item::Omega,
        ]))
    });

    info!("Booting up HTTP server. Listening on port {}.", app.port);
    let server = add_to_basket.or(list_items).recover(handle_rejection);
    warp::serve(server).run(([0, 0, 0, 0], app.port)).await;
    Ok(())
}

fn handle_add_basket(
    client: concordium_rust_sdk::endpoints::Client,
    state: Arc<Mutex<Server>>,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::body::json().and_then(move |request: AddBasketRequest| {
        let client = client.clone();
        let state = Arc::clone(&state);
        async move {
            info!("Queried for creating an identity");
            match validate_worker(client.clone(), state, request).await {
                Ok(r) => Ok(warp::reply::json(&r)),
                Err(e) => {
                    warn!("Request is invalid {:#?}.", e);
                    Err(warp::reject::custom(e))
                }
            }
        }
    })
}

#[derive(Debug)]
/// An internal error type used by this server to manage error handling.
#[derive(thiserror::Error)]
enum AddBasketError {
    #[error("Not allowed")]
    NotAllowed,
    #[error("Invalid proof")]
    InvalidProofs,
    #[error("Node access error: {0}")]
    NodeAccess(#[from] QueryError),
}

impl From<RPCError> for AddBasketError {
    fn from(err: RPCError) -> Self { Self::NodeAccess(err.into()) }
}

impl warp::reject::Reject for AddBasketError {}

#[derive(serde::Serialize)]
/// Response in case of an error. This is going to be encoded as a JSON body
/// with fields 'code' and 'message'.
struct ErrorResponse {
    code:    u16,
    message: String,
}

/// Helper function to make the reply.
fn mk_reply(message: String, code: StatusCode) -> impl warp::Reply {
    let msg = ErrorResponse {
        message: message.into(),
        code:    code.as_u16(),
    };
    warp::reply::with_status(warp::reply::json(&msg), code)
}

async fn handle_rejection(err: Rejection) -> Result<impl warp::Reply, Infallible> {
    if err.is_not_found() {
        let code = StatusCode::NOT_FOUND;
        let message = "Not found.";
        Ok(mk_reply(message.into(), code))
    } else if let Some(AddBasketError::NotAllowed) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Needs proof.";
        Ok(mk_reply(message.into(), code))
    } else if let Some(AddBasketError::InvalidProofs) = err.find() {
        let code = StatusCode::BAD_REQUEST;
        let message = "Invalid proofs.";
        Ok(mk_reply(message.into(), code))
    } else if let Some(AddBasketError::NodeAccess(e)) = err.find() {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        let message = format!("Cannot access the node: {}", e);
        Ok(mk_reply(message, code))
    } else if err
        .find::<warp::filters::body::BodyDeserializeError>()
        .is_some()
    {
        let code = StatusCode::BAD_REQUEST;
        let message = "Malformed body.";
        Ok(mk_reply(message.into(), code))
    } else {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        let message = "Internal error.";
        Ok(mk_reply(message.into(), code))
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct AddBasketRequest {
    item:  Item,
    proof: Option<AgeProofOutput>,
}

/// A common function that validates the cryptographic proofs in the request.
async fn validate_worker(
    mut client: concordium_rust_sdk::endpoints::Client,
    state: Arc<Mutex<Server>>,
    request: AddBasketRequest,
) -> Result<Basket, AddBasketError> {
    if request.item <= Item::Gamma {
        let mut server = state.lock().expect("Failed to lock");
        server.basket.basket.push(request.item);
        let rv = server.basket.clone();
        Ok(rv)
    } else if let Some(proof) = request.proof {
        let consensus_info = client.get_consensus_status().await?;
        let acc_info = client
            .get_account_info(&proof.account, &consensus_info.last_finalized_block)
            .await?;
        let credential = acc_info
            .account_credentials
            .get(&0.into())
            .expect("No credential on account with given index"); // Read the relevant credential from chain that the claim is about.
        let commitments = match &credential.value {
            AccountCredentialWithoutProofs::Initial { icdv: _, .. } => {
                return Err(AddBasketError::NotAllowed);
            }
            AccountCredentialWithoutProofs::Normal {
                commitments,
                cdv: _,
            } => commitments,
        };

        let cmm = if let Some(cmm) = commitments.cmm_attributes.get(&AttributeTag(3)) {
            cmm
        } else {
            return Err(AddBasketError::NotAllowed);
        };

        let mut server = state.lock().expect("Failed to lock");
        if verify_attribute_range(
            &server.global_context.on_chain_commitment_key,
            server.global_context.bulletproof_generators(),
            &proof.lower,
            &proof.upper,
            cmm,
            &proof.proof,
        )
        .is_err()
        {
            Err(AddBasketError::InvalidProofs)
        } else {
            server.basket.basket.push(request.item);
            let rv = server.basket.clone();
            Ok(rv)
        }
    } else {
        Err(AddBasketError::NotAllowed)
    }
}
