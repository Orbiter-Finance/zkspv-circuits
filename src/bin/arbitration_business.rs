use std::fs::File;
use std::io::BufReader;

use ethers_core::types::H256;
use serde_json::Value;
use zkspv_circuits::arbitration::router::ProofRouter;
use zkspv_circuits::server::OriginalProof;

fn main() {
    // let arbitration_data_file =
    //     File::open("test_data/from_ethereum_to_zksync_era_source.json").unwrap();
    let arbitration_data_file =
        File::open("test_data/from_ethereum_to_zksync_era_dest.json").unwrap();

    // let arbitration_data_file =
    //     File::open("test_data/from_zksync_era_to_ethereum_source.json").unwrap();

    // let arbitration_data_file =
    //     File::open("test_data/from_zksync_era_to_ethereum_dest.json").unwrap();

    let data_reader = BufReader::new(arbitration_data_file);
    let proof_str: Value = serde_json::from_reader(data_reader).unwrap();

    let op = OriginalProof { task_id: H256([0u8; 32]), proof: proof_str.to_string() };
    let constructor = op.get_constructor_by_parse_proof();

    let task = ProofRouter::new(constructor, 1);
    let _proof = task.get_calldata(true);
}
