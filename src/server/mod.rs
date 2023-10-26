use crate::config::api::get_internal_api;
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Params, Value};
use jsonrpc_http_server::ServerBuilder;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, Deserialize)]
pub struct OriginalProof {
    pub chain_id: u64,
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: u64,
}

pub fn start_rpc_server() {
    let mut io = IoHandler::default();

    io.add_method("generate_proof", |params: Params| async move {
        let original_proof: OriginalProof = params.parse().unwrap();
        println!("chain_id{}", original_proof.chain_id);
        let response = Response { status: 200 };
        let serialized = serde_json::to_string(&response).unwrap();
        Ok(Value::String(serialized))
    });
    let addr = get_internal_api();

    let server = ServerBuilder::new(io).threads(3).start_http(&addr.parse().unwrap()).unwrap();

    server.wait();
}

#[test]
fn test_start_rpc_server() {
    start_rpc_server()
}
