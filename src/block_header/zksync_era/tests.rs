use crate::block_header::zksync_era::ZkSyncEraBlockHeaderChainCircuit;
use crate::halo2_proofs::dev::MockProver;
use crate::rlp::builder::RlcThreadBuilder;
use crate::util::helpers::get_provider;
use crate::util::{EthConfigPinning, Halo2ConfigPinning};
use crate::{EthPreCircuit, Network, ZkSyncEraNetwork};
use ethers_core::types::{H256, U256};
use ethers_core::utils::keccak256;
use std::env::set_var;
use std::str::FromStr;

pub fn get_test_circuit(
    blocks_number: Vec<u64>,
    network: Network,
) -> ZkSyncEraBlockHeaderChainCircuit {
    let provider = get_provider(&network);
    ZkSyncEraBlockHeaderChainCircuit::from_provider(&provider, network, blocks_number)
}

#[test]
pub fn test_mainnet_block_header() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigPinning::from_path("configs/tests/zksync_era_block.json").params;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree; //0x123b8cc 0x11be9fe
    let input = get_test_circuit(vec![0x11be9ff], Network::ZkSync(ZkSyncEraNetwork::Mainnet));
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
pub fn test_zksync_goerli_block_header() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigPinning::from_path("configs/tests/zksync_era_block.json").params;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree; //0xd20633 0xd2064f
    let input = get_test_circuit(vec![0xd2064f], Network::ZkSync(ZkSyncEraNetwork::Goerli));
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

pub fn miniblock_hash(
    miniblock_number: u64,
    miniblock_timestamp: u64,
    prev_miniblock_hash: H256,
    txs_rolling_hash: H256,
) -> H256 {
    let mut digest: [u8; 128] = [0u8; 128];
    U256::from(miniblock_number).to_big_endian(&mut digest[0..32]);
    U256::from(miniblock_timestamp).to_big_endian(&mut digest[32..64]);
    digest[64..96].copy_from_slice(prev_miniblock_hash.as_bytes());
    digest[96..128].copy_from_slice(txs_rolling_hash.as_bytes());

    H256(keccak256(&digest))
}

#[test]
fn test_hash() {
    let prev_miniblock_hash =
        "8f06f2682f1f00c2549714f4fb2ac8983ab50b1e754f6a83b5398de874b016aa".parse().unwrap();

    let txs = vec![
        H256::from_str("0xaedc36484e78b4575c6fd1887741ee5a13f0f1fc90155c24a9bb48604832773f")
            .unwrap(),
        H256::from_str("0xe5acfd25bb4c9df418162183dd3ea223d8413252c53ccca9d2c8fe8892a91dad")
            .unwrap(),
        H256::from_str("0x91ad38fe2d38e3221c1d79dd81bbc0ffbcb9c446add68425aafbb69b2569f4c1")
            .unwrap(),
        H256::from_str("0x6ba8067e237de18c831e9dc669e5a88e26266a5123ad758f1db3a8bcee45fbb2")
            .unwrap(),
        H256::from_str("0x755994b273941a9f92af5a7cb555ca8b246615a2d7b49dcab05b54738ee15858")
            .unwrap(),
        H256::from_str("0xbc57a626fc280428c97261c056f9018cd9a21bf9d30f9105fcd059682c24f2e0")
            .unwrap(),
        H256::from_str("0x4f9d971479fc60f9be3e6d52412ccd1853d1c1477ed2dcb4544d9fafd3362b5a")
            .unwrap(),
        H256::from_str("0xeeb7f24b96d2361775170362e1a66581037d1565f40de0037784eb9740c3bd1e")
            .unwrap(),
        H256::from_str("0x0f2f7b973d64216a316798895dde4c7251e76cdb629d5cd63481298e9f12e7f2")
            .unwrap(),
        H256::from_str("0xf8021b7470e93aa18c713ab74d572ef2d436c17e5c9004497911d08f34e3de85")
            .unwrap(),
        H256::from_str("0x728e2d4895757a83774b58b8c26472faf5a1394a12eb04bf91a5ba1aa0afb8f8")
            .unwrap(),
        H256::from_str("0x67a2127185f95ac686df5092bc3c9e1ffe75ef7fb3b4b542fbeacc67561ace2b")
            .unwrap(),
        H256::from_str("0xc69dc891c70ca8df4db6de2aec70fcc8022764b0ad0e9c11813c888b3930e934")
            .unwrap(),
        H256::from_str("0xb8566eb81400f05bf4a95cba1ba97fabfbaca09694065c731d7401b3feeb33b1")
            .unwrap(),
        H256::from_str("0xfaa3c4bfb1f099703c84ab3d69d760155908ae2a5df214d891ab5b61f34a3ddb")
            .unwrap(),
    ];
    let mut txs_rolling_hash = H256::zero();
    for current_tx in txs.iter() {
        txs_rolling_hash =
            H256::from(keccak256([txs_rolling_hash.as_bytes(), current_tx.as_bytes()].concat()))
    }
    println!("txs_rolling_hash:{:?}", txs_rolling_hash);
    let r = miniblock_hash(0x11be9fe, 0x654ddede, prev_miniblock_hash, txs_rolling_hash);
    println!("r:{:?}", r);
}
