use std::env::set_var;

use ethers_core::types::Bytes;
use hex::FromHex;

use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::Fr,
};
use crate::{ Network, OptimismNetwork};
use crate::receipt::optimism::EthBlockReceiptCircuit;
use crate::rlp::builder::RlcThreadBuilder;
use crate::util::EthConfigParams;
use crate::util::helpers::get_provider;

fn get_test_circuit(
    receipt_index: u32,
    receipt_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    network: Network,
) -> EthBlockReceiptCircuit {
    let provider = get_provider(&network);
    let mut block_number = 0;
    match network {
        Network::Optimism(OptimismNetwork::Mainnet) => {
            block_number = 16356350;
        }
        Network::Optimism(OptimismNetwork::Goerli) => {
            block_number = 0x82e239;
        }

        _ => {}
    }
    EthBlockReceiptCircuit::from_provider(&provider, block_number, receipt_index, receipt_rlp, merkle_proof, 4, network)
}


#[test]
pub fn test_receipt_mpt() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("../../../configs/tests/receipt.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let receipt_index = 240;
    let receipt_rlp = Vec::from_hex("02f9010a018401c92afbb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0").unwrap();

    let proof_one_bytes = Vec::from_hex("f90131a0cd835eed90dc62ce38fc629e51135f41e4d6aa8297eb209e2a0e0671018671fda0f9a68953fd2a873d37cd9d77ba72b40ce3e3ebba2b08e9f31117ce4d0076016fa0f8cd15d6e2f1da0fc5a32881d2733ce4ffd4c3363dd2e01aa60e3560cf7d0e21a04580b1c0158089a149266dfc2448ce2d1a261bc1bb0fbd2fbebaa9c546370de9a0146b084e33164f7f9628b2207ab03ec986d18ee35ec2e1038120ce575ca929e2a097123f7f2c8965f6295bd47bd639c668ae30d6aec263e2de142cf1bfbe32e4dba03af49cc7095ad31c0f86325c5d85597d58e58b05c3e9177b1baa376225d4fe6ca0482815b84f97732ddfe82629cf723714af9e87dd8b8fada48b4ba00e0d5627f0a04c4c54f8fa0a307cb071376f56b064d592e30aaf0c53bd7b660f6327619168908080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);

    let proof_two_bytes = Vec::from_hex("f851a0e58dd61cabd537ab61ea18ce0e73f9414c8cfa7248dfbf050e33777a3492563da0043448043dc9fe8fa19b0e5a77e89193fe4548c9a0d070a47b3da979f5f1a3da808080808080808080808080808080").unwrap();
    let proof_two = Bytes::from(proof_two_bytes);

    let proof_three_bytes = Vec::from_hex("f901118080808080808080a055c4286cdacf4bc3f571bd3f0215d5402a0a0b77d694cba476d2e3b965b7fd3da0b05156e8ec07d328fc5543686778607ca90c041e9544284e0df15a665f8dcdbea04a7ea09229cc14ca0f7232a1ce05b13229bccae0dd8b3ac9167805cdde49896fa086eae439a8355d848653bcfb4cd87dc9657e991fd15fb856b15a4dd4bc372c96a0737a439905e088647b23aa2b28975929ff1e543fa07887e5fd226b79d40d806fa04dbc7ed71dda6e4287f7978f78875e17665772f493b9cf1754f5002a1c0f2349a015e9ebc7bda8a58a7496fda6983649aedd29d49b0a730011e66536549d1d9a6ba0dc178b0312161c3910f841cf826d0f652ff92f8fe205cf7f9078c2b7c4f9d13680").unwrap();
    let proof_three = Bytes::from(proof_three_bytes);

    let proof_four_bytes = Vec::from_hex("f9011230b9010e02f9010a018401c92afbb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0").unwrap();
    let proof_four = Bytes::from(proof_four_bytes);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three, proof_four];
    let input = get_test_circuit(receipt_index, receipt_rlp, merkle_proof, Network::Optimism(OptimismNetwork::Goerli));
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);
    // println!("instance:{:?}", circuit);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();

    Ok(())
}