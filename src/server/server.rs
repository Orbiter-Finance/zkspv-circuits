// use crate::server::client::send_to_client;
// use crate::server::execute::execute_proof;
// use chrono::{DateTime, Local};
// use clap::builder::Str;
// use jsonrpsee::core::{async_trait, RpcResult};
// use jsonrpsee::proc_macros::rpc;
// use serde::{Deserialize, Serialize};
// use serde_json::Value;
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct OriginalProof {
//     pub chain_id: u64,
//     pub source: bool,
//     pub proof: String,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct Response {
//     pub status: u64,
// }
//
// #[rpc(server, client)]
// pub trait ZkpRpc {
//     #[method(name = "GenerateProof")]
//     async fn generate_proof(&self, op: OriginalProof) -> RpcResult<Value>;
// }
//
// pub struct RpcServerImpl;
//
// #[async_trait]
// impl ZkpRpcServer for RpcServerImpl {
//     async fn generate_proof(&self, op: OriginalProof) -> RpcResult<Value> {
//         let now: DateTime<Local> = Local::now();
//         let formatted = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));
//
//         tokio::spawn(async move {
//             println!("original_proof{}", op.chain_id);
//             println!("original_proof{}", op.source);
//             // execute_proof(&op);
//             send_to_client().await.unwrap();
//             let now: DateTime<Local> = Local::now();
//             let formatted = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));
//         });
//
//         let now: DateTime<Local> = Local::now();
//         let formatted = format!("{}", now.format("%Y-%m-%d %H:%M:%S"));
//         let response = Response { status: 200 };
//         let serialized = serde_json::to_string(&response).unwrap();
//         Ok(Value::String(serialized))
//     }
// }
