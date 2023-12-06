use base64::{engine::general_purpose, Engine as _};
use ethers_core::types::H256;
use hex::FromHex;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;

use crate::config::api::get_spv_client_api;
pub const GENERATE_SUCCESS: usize = 1;
pub const GENERATE_FAILED: usize = 0;
pub async fn send_to_client(task_id: H256, proof: String, status: usize) -> anyhow::Result<()> {
    let url = &format!("http://{}", get_spv_client_api());
    let client = HttpClientBuilder::default().build(url).unwrap();
    let proof_bytes = Vec::from_hex(proof).unwrap();
    let proof_base64 = general_purpose::STANDARD_NO_PAD.encode(proof_bytes);
    let params = rpc_params![task_id, proof_base64, status.to_string(), ""];
    let response: String = client.request("ReturnToProof", params).await?;
    println!("response: {:?}", response);

    Ok(())
}
