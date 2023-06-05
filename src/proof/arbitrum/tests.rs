use std::env::set_var;

use ethers_core::types::{BlockId, Bytes, H256};
use hex::FromHex;
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::Fr,
};
use crate::{ArbitrumNetwork, EthereumNetwork, Network};
use crate::proof::arbitrum::{ArbitrumProofBlockTrack, ArbitrumProofCircuit, ArbitrumProofTransactionOrReceipt};
use crate::rlp::builder::RlcThreadBuilder;
use crate::util::EthConfigParams;
use crate::util::helpers::get_provider;

fn get_arbitrum_proof_test_circuit(
    l2_seq_num:u64,
    transaction_or_receipt:Vec<ArbitrumProofTransactionOrReceipt>,
    trace_blocks:Vec<ArbitrumProofBlockTrack>,
    arbitrum_network: Network,
    ethereum_network: Network,
) -> ArbitrumProofCircuit {
    let arbitrum_provider = get_provider(&arbitrum_network);
    let ethereum_provider = get_provider(&ethereum_network);
    ArbitrumProofCircuit::from_provider(
        &arbitrum_provider,
        &ethereum_provider,
        l2_seq_num,
        transaction_or_receipt,
        trace_blocks,
        arbitrum_network,
        ethereum_network
    )
}

#[test]
pub fn test_arbitrum_proof() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/arbitrum_proof.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let l2_seq_num = 10;
    let arbitrum_transaction_index = 1;
    let (arbitrum_transaction_rlp, arbitrum_transaction_merkle_proof, arbitrum_transaction_pf_max_depth) = get_arbitrum_transaction_rlp_and_merkle_proof_and_max_depth();
    let arbitrum_transaction = ArbitrumProofTransactionOrReceipt{
        index: arbitrum_transaction_index,
        rlp: arbitrum_transaction_rlp,
        merkle_proof: arbitrum_transaction_merkle_proof,
        pf_max_depth: arbitrum_transaction_pf_max_depth,
    };

    let arbitrum_receipt_index = 2;
    let (arbitrum_receipt_rlp, arbitrum_receipt_merkle_proof, arbitrum_receipt_pf_max_depth) = get_arbitrum_receipt_rlp_and_merkle_proof_and_max_depth();
    let arbitrum_receipt = ArbitrumProofTransactionOrReceipt{
        index: arbitrum_receipt_index,
        rlp: arbitrum_receipt_rlp,
        merkle_proof: arbitrum_receipt_merkle_proof,
        pf_max_depth: arbitrum_receipt_pf_max_depth,
    };

    let ethereum_transaction_index = 1;
    let (ethereum_transaction_rlp, ethereum_transaction_merkle_proof, ethereum_transaction_pf_max_depth) = get_ethereum_transaction_rlp_and_merkle_proof_and_max_depth();
    let ethereum_transaction = ArbitrumProofTransactionOrReceipt{
        index: ethereum_transaction_index,
        rlp: ethereum_transaction_rlp,
        merkle_proof: ethereum_transaction_merkle_proof,
        pf_max_depth: ethereum_transaction_pf_max_depth,
    };

    let transaction_or_receipt = vec![arbitrum_transaction,arbitrum_receipt,ethereum_transaction];

    let arbitrum_trace_block_start = 20168575;
    let arbitrum_trace_block_end = "0xdc3e2c87b862b10927798b2a0bf91456f3c6fbad4f33438c7ca275c87dd33e1a".parse::<H256>().unwrap();
    let arbitrum_trace_block_end = BlockId::from(arbitrum_trace_block_end);
    let arbitrum_trace_block=ArbitrumProofBlockTrack{
        start_block: arbitrum_trace_block_start,
        end_block: arbitrum_trace_block_end,
    };
    let ethereum_trace_block_start = 9015126;
    let ethereum_trace_block_end = "0x2480e2bfc86d6ec7a73793308eae3a401f46acb4184ad8875798b66ecb8d8053".parse::<H256>().unwrap();
    let ethereum_trace_block_end = BlockId::from(ethereum_trace_block_end);
    let ethereum_trace_block=ArbitrumProofBlockTrack{
        start_block:ethereum_trace_block_start,
        end_block:ethereum_trace_block_end,
    };
    let trace_blocks=vec![arbitrum_trace_block,ethereum_trace_block];

    let arbitrum_network = Network::Arbitrum(ArbitrumNetwork::Goerli);
    let ethereum_network = Network::Ethereum(EthereumNetwork::Goerli);


    let input = get_arbitrum_proof_test_circuit(
        l2_seq_num,
        transaction_or_receipt,
        trace_blocks,
        arbitrum_network,
        ethereum_network,
    );
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);
    println!("instance:{:?}", circuit.instance());
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

fn get_arbitrum_transaction_rlp_and_merkle_proof_and_max_depth() -> (Vec<u8>, Vec<Bytes>, usize) {
    let transaction_rlp = Vec::from_hex("02f9010a018401c92afbb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0").unwrap();

    let proof_one_bytes = Vec::from_hex("f90131a0cd835eed90dc62ce38fc629e51135f41e4d6aa8297eb209e2a0e0671018671fda0f9a68953fd2a873d37cd9d77ba72b40ce3e3ebba2b08e9f31117ce4d0076016fa0f8cd15d6e2f1da0fc5a32881d2733ce4ffd4c3363dd2e01aa60e3560cf7d0e21a04580b1c0158089a149266dfc2448ce2d1a261bc1bb0fbd2fbebaa9c546370de9a0146b084e33164f7f9628b2207ab03ec986d18ee35ec2e1038120ce575ca929e2a097123f7f2c8965f6295bd47bd639c668ae30d6aec263e2de142cf1bfbe32e4dba03af49cc7095ad31c0f86325c5d85597d58e58b05c3e9177b1baa376225d4fe6ca0482815b84f97732ddfe82629cf723714af9e87dd8b8fada48b4ba00e0d5627f0a04c4c54f8fa0a307cb071376f56b064d592e30aaf0c53bd7b660f6327619168908080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);

    let proof_two_bytes = Vec::from_hex("f851a0e58dd61cabd537ab61ea18ce0e73f9414c8cfa7248dfbf050e33777a3492563da0043448043dc9fe8fa19b0e5a77e89193fe4548c9a0d070a47b3da979f5f1a3da808080808080808080808080808080").unwrap();
    let proof_two = Bytes::from(proof_two_bytes);

    let proof_three_bytes = Vec::from_hex("f901118080808080808080a055c4286cdacf4bc3f571bd3f0215d5402a0a0b77d694cba476d2e3b965b7fd3da0b05156e8ec07d328fc5543686778607ca90c041e9544284e0df15a665f8dcdbea04a7ea09229cc14ca0f7232a1ce05b13229bccae0dd8b3ac9167805cdde49896fa086eae439a8355d848653bcfb4cd87dc9657e991fd15fb856b15a4dd4bc372c96a0737a439905e088647b23aa2b28975929ff1e543fa07887e5fd226b79d40d806fa04dbc7ed71dda6e4287f7978f78875e17665772f493b9cf1754f5002a1c0f2349a015e9ebc7bda8a58a7496fda6983649aedd29d49b0a730011e66536549d1d9a6ba0dc178b0312161c3910f841cf826d0f652ff92f8fe205cf7f9078c2b7c4f9d13680").unwrap();
    let proof_three = Bytes::from(proof_three_bytes);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];

    let pf_max_depth = merkle_proof.len().clone();

    (transaction_rlp, merkle_proof, pf_max_depth)
}

fn get_arbitrum_receipt_rlp_and_merkle_proof_and_max_depth() -> (Vec<u8>, Vec<Bytes>, usize) {
    let receipt_rlp = Vec::from_hex("02f9010a018401c92afbb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0").unwrap();

    let proof_one_bytes = Vec::from_hex("f90131a0cd835eed90dc62ce38fc629e51135f41e4d6aa8297eb209e2a0e0671018671fda0f9a68953fd2a873d37cd9d77ba72b40ce3e3ebba2b08e9f31117ce4d0076016fa0f8cd15d6e2f1da0fc5a32881d2733ce4ffd4c3363dd2e01aa60e3560cf7d0e21a04580b1c0158089a149266dfc2448ce2d1a261bc1bb0fbd2fbebaa9c546370de9a0146b084e33164f7f9628b2207ab03ec986d18ee35ec2e1038120ce575ca929e2a097123f7f2c8965f6295bd47bd639c668ae30d6aec263e2de142cf1bfbe32e4dba03af49cc7095ad31c0f86325c5d85597d58e58b05c3e9177b1baa376225d4fe6ca0482815b84f97732ddfe82629cf723714af9e87dd8b8fada48b4ba00e0d5627f0a04c4c54f8fa0a307cb071376f56b064d592e30aaf0c53bd7b660f6327619168908080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);

    let proof_two_bytes = Vec::from_hex("f851a0e58dd61cabd537ab61ea18ce0e73f9414c8cfa7248dfbf050e33777a3492563da0043448043dc9fe8fa19b0e5a77e89193fe4548c9a0d070a47b3da979f5f1a3da808080808080808080808080808080").unwrap();
    let proof_two = Bytes::from(proof_two_bytes);

    let proof_three_bytes = Vec::from_hex("f901118080808080808080a055c4286cdacf4bc3f571bd3f0215d5402a0a0b77d694cba476d2e3b965b7fd3da0b05156e8ec07d328fc5543686778607ca90c041e9544284e0df15a665f8dcdbea04a7ea09229cc14ca0f7232a1ce05b13229bccae0dd8b3ac9167805cdde49896fa086eae439a8355d848653bcfb4cd87dc9657e991fd15fb856b15a4dd4bc372c96a0737a439905e088647b23aa2b28975929ff1e543fa07887e5fd226b79d40d806fa04dbc7ed71dda6e4287f7978f78875e17665772f493b9cf1754f5002a1c0f2349a015e9ebc7bda8a58a7496fda6983649aedd29d49b0a730011e66536549d1d9a6ba0dc178b0312161c3910f841cf826d0f652ff92f8fe205cf7f9078c2b7c4f9d13680").unwrap();
    let proof_three = Bytes::from(proof_three_bytes);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];

    let pf_max_depth = merkle_proof.len().clone();

    (receipt_rlp, merkle_proof, pf_max_depth)
}

fn get_ethereum_transaction_rlp_and_merkle_proof_and_max_depth() -> (Vec<u8>, Vec<Bytes>, usize) {
    let receipt_rlp = Vec::from_hex("02f9010a018401c92afbb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0").unwrap();

    let proof_one_bytes = Vec::from_hex("f90131a0cd835eed90dc62ce38fc629e51135f41e4d6aa8297eb209e2a0e0671018671fda0f9a68953fd2a873d37cd9d77ba72b40ce3e3ebba2b08e9f31117ce4d0076016fa0f8cd15d6e2f1da0fc5a32881d2733ce4ffd4c3363dd2e01aa60e3560cf7d0e21a04580b1c0158089a149266dfc2448ce2d1a261bc1bb0fbd2fbebaa9c546370de9a0146b084e33164f7f9628b2207ab03ec986d18ee35ec2e1038120ce575ca929e2a097123f7f2c8965f6295bd47bd639c668ae30d6aec263e2de142cf1bfbe32e4dba03af49cc7095ad31c0f86325c5d85597d58e58b05c3e9177b1baa376225d4fe6ca0482815b84f97732ddfe82629cf723714af9e87dd8b8fada48b4ba00e0d5627f0a04c4c54f8fa0a307cb071376f56b064d592e30aaf0c53bd7b660f6327619168908080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);

    let proof_two_bytes = Vec::from_hex("f851a0e58dd61cabd537ab61ea18ce0e73f9414c8cfa7248dfbf050e33777a3492563da0043448043dc9fe8fa19b0e5a77e89193fe4548c9a0d070a47b3da979f5f1a3da808080808080808080808080808080").unwrap();
    let proof_two = Bytes::from(proof_two_bytes);

    let proof_three_bytes = Vec::from_hex("f901118080808080808080a055c4286cdacf4bc3f571bd3f0215d5402a0a0b77d694cba476d2e3b965b7fd3da0b05156e8ec07d328fc5543686778607ca90c041e9544284e0df15a665f8dcdbea04a7ea09229cc14ca0f7232a1ce05b13229bccae0dd8b3ac9167805cdde49896fa086eae439a8355d848653bcfb4cd87dc9657e991fd15fb856b15a4dd4bc372c96a0737a439905e088647b23aa2b28975929ff1e543fa07887e5fd226b79d40d806fa04dbc7ed71dda6e4287f7978f78875e17665772f493b9cf1754f5002a1c0f2349a015e9ebc7bda8a58a7496fda6983649aedd29d49b0a730011e66536549d1d9a6ba0dc178b0312161c3910f841cf826d0f652ff92f8fe205cf7f9078c2b7c4f9d13680").unwrap();
    let proof_three = Bytes::from(proof_three_bytes);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];

    let pf_max_depth = merkle_proof.len().clone();

    (receipt_rlp, merkle_proof, pf_max_depth)
}