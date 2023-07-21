use jsonrpc_http_server::jsonrpc_core::{IoHandler, Params, Value};
use jsonrpc_http_server::ServerBuilder;
use crate::config::api::get_internal_api;

pub fn start_rpc_server() {
    let mut io = IoHandler::default();

    io.add_method("internal_generate_proof", |_params: Params| async {
        // let s = test_1559_transaction_mpt();

        Ok(Value::String("hello1".to_owned()))
    });
    let addr = get_internal_api();

    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&addr.parse().unwrap())
        .unwrap();

    server.wait();
}

#[test]
fn main(){
    start_rpc_server()
}