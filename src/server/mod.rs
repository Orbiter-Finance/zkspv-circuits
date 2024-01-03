pub mod server;

use crate::config::api::get_internal_api;
use crate::db::ChallengesStorage;
use ethers_core::types::H256;
use hyper::Method;
use jsonrpsee::server::{RpcModule, Server};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal::ctrl_c;
use tokio::sync::mpsc::UnboundedSender;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone, Debug, Deserialize)]
pub struct OriginalProof {
    pub task_id: H256,
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct QueryChallenge {
    pub challenge_id: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryChallengeOutput {
    pub challenge_id: H256,
    pub proof: Option<String>,
    pub status: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: u64,
}

pub async fn init_server(
    tx: UnboundedSender<OriginalProof>,
    challenges_storage: Arc<Mutex<ChallengesStorage>>,
) -> std::io::Result<()> {
    let tx = Arc::new(tx);
    let cors = CorsLayer::new()
        // Allow `POST` when accessing the resource
        .allow_methods([Method::POST])
        // Allow requests from any origin
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new().layer(cors);

    let server = Server::builder()
        .set_middleware(middleware)
        .build(get_internal_api().parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let mut module = RpcModule::new(());

    module
        .register_method("generate_proof", move |params, c| {
            let tx = tx.clone();
            let original_proof: OriginalProof = params.parse().unwrap();
            tokio::spawn(async move {
                tx.send(original_proof).unwrap();
            });

            let response = Response { status: 200 };
            let serialized = serde_json::to_string(&response).unwrap();
            Value::String(serialized)
        })
        .unwrap();

    module
        .register_method("get_challenge_proof", move |params, c| {
            let challenges_storage = challenges_storage.clone();
            let mut storage = challenges_storage.lock();

            let query_challenge: QueryChallenge = params.parse().unwrap();
            let challenge_proof = storage.get_proof_by_challenge_id(query_challenge.challenge_id);
            let mut status = 0;
            let mut proof = None;
            match challenge_proof {
                Ok(Some(value)) => {
                    if value.is_empty() {
                        status = 2;
                    } else {
                        status = 1;
                        proof = Some(String::from_utf8(value).unwrap());
                    }
                }
                Ok(None) => status = 0,
                Err(e) => println!("operational problem encountered: {}", e),
            }
            let response =
                QueryChallengeOutput { challenge_id: query_challenge.challenge_id, proof, status };
            let serialized = serde_json::to_string(&response).unwrap();
            Value::String(serialized)
        })
        .unwrap();

    let addr = server.local_addr().unwrap();

    info!(target: "app","Spv Pool server listening on {:?}",addr.to_string());

    let handle = server.start(module);

    tokio::select! {
        _ = ctrl_c() => println!("receive Ctrl C"),
    }
    handle.stop().unwrap();
    Ok(())
}
