use crate::config::api::get_spv_client_api;
use jsonrpsee::core::client::{Client, ClientBuilder, ClientT};
use jsonrpsee::http_client::transport::HttpTransportClient;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;

// use jsonrpc::simple_http::{self, SimpleHttpTransport};
// use jsonrpc::Client;
// use serde_json::value::RawValue;
//
// fn client(url: &str) -> Result<Client, simple_http::Error> {
//     let t = SimpleHttpTransport::builder().url(url)?.build();
//
//     Ok(Client::with_transport(t))
// }
//
pub async fn send_to_client() -> anyhow::Result<()> {
    let uri = &format!("http://{}", get_spv_client_api());

    let client = HttpClientBuilder::default().build(uri).unwrap();
    let params = rpc_params![1_u64, 2, 3];
    let response: String = client.request("ReturnToProof", params).await?;
    println!("response: {:?}", response);

    Ok(())
}
// // Demonstrate an example JSON-RCP call against bitcoind.
// #[test]
// fn test_send() {
//     let client = client("localhost:8100").expect("failed to create client");
//     let params = [
//         "http://127.0.0.1:8080/testMakerUrl".to_string(),
//         "0x855a26127e84fa3311f2e1df0e9eb74966c87290ff97ab013bed6899b41e2d70".to_string(),
//         "5".to_string(),
//         "0x19924027e0e9804d2316aC7ADf189128Bcbe1369".to_string(),
//         "0x4aa86B397D9A7242cc9F5576b13e830fBC6FfFb6".to_string(),
//     ];
//     let o1 = RawValue::from_string("5".to_string()).unwrap();
//     let o2 = RawValue::from_string(
//         "0x855a26127e84fa3311f2e1df0e9eb74966c87290ff97ab013bed6899b41e2d70".to_string(),
//     )
//     .unwrap();
//     let o3 = RawValue::from_string("5".to_string()).unwrap();
//     let o4 =
//         RawValue::from_string("0x19924027e0e9804d2316aC7ADf189128Bcbe1369".to_string()).unwrap();
//     let o5 =
//         RawValue::from_string("0x4aa86B397D9A7242cc9F5576b13e830fBC6FfFb6".to_string()).unwrap();
//     let o = [o1, o2, o3, o4, o5];
//     let o = o.as_slice();
//     let request = client.build_request("GenerateSourceTxProof", o);
//     let response = client.send_request(request).expect("send_request failed");
//
//     // For other commands this would be a struct matching the returned json.
//     let result: u64 = response.result().expect("response is an error, use check_error");
//     println!("bitcoind uptime: {}", result);
// }
