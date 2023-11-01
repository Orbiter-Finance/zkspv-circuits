pub mod client;
pub mod execute;
pub mod server;

use crate::config::api::get_internal_api;
use crate::server::client::send_to_client;
// use crate::server::server::{RpcServerImpl, ZkpRpcServer};
use chrono::{DateTime, Local};
use hyper::Method;
use jsonrpsee::server::{RpcModule, Server};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::sleep;
use std::{thread, time};
use tokio::signal::ctrl_c;
use tokio::sync::mpsc::UnboundedSender;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone, Debug, Deserialize)]
pub struct OriginalProof {
    pub chain_id: u64,
    pub source: bool,
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: u64,
}

// #[tokio::main]
pub async fn init_server(tx: UnboundedSender<OriginalProof>) -> std::io::Result<()> {
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
            let now: DateTime<Local> = Local::now();
            let formatted = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));
            println!("Time the request was received:{:?}", formatted);
            let tx = tx.clone();
            let original_proof: OriginalProof = params.parse().unwrap();
            tokio::spawn(async move {
                tx.send(original_proof).unwrap();
            });
            // tokio::spawn(async move {
            //     execute(&original_proof);
            //     let now: DateTime<Local> = Local::now();
            //     let formatted = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));
            //     println!("Time to send results to client:{:?}", formatted);
            // });

            let now: DateTime<Local> = Local::now();
            let formatted = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));
            println!("Time to reply to request:{:?}", formatted);
            let response = Response { status: 200 };
            let serialized = serde_json::to_string(&response).unwrap();
            Value::String(serialized)
        })
        .unwrap();
    let addr = server.local_addr().unwrap();

    let handle = server.start(module);

    tokio::select! {
        _ = ctrl_c() => println!("receive Ctrl C"),
    }
    handle.stop().unwrap();
    Ok(())
}
