use std::fs::File;
use std::io::BufReader;

use ethers_core::types::H256;
use serde_json::Value;
use zkspv_circuits::arbitration::router::ProofRouter;
use zkspv_circuits::server::execute::parse_original_proof;
use zkspv_circuits::server::OriginalProof;

fn main() {
    let arbitration_data_file = File::open("test_data/arbitration_mock_data.json").unwrap();

    let data_reader = BufReader::new(arbitration_data_file);
    // let eth_: EthereumSourceProof = serde_json::from_reader(data_reader).unwrap();
    let proof_str: Value = serde_json::from_reader(data_reader).unwrap();

    let proofs_router = parse_original_proof(OriginalProof {
        task_id: H256([0u8; 32]),
        chain_id: 5, // goerli
        source: true,
        proof: proof_str.to_string(),
    });
    let task = ProofRouter::new(proofs_router.unwrap(), 1);
    let proof = task.get_calldata(true);
}
