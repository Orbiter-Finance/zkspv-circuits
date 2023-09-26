use std::str::FromStr;

use ethers_core::types::H256;
use ethers_core::types::{Address, Bytes};
use hex::FromHex;

use crate::util::helpers::calculate_mk_address_struct;
use crate::{
    config::contract::get_mdc_config, util::helpers::get_provider, EthereumNetwork, Network,
};

use super::EthBlockStorageCircuit;

#[derive(Clone, Debug)]
pub struct EbcRuleParams {
    pub ebc_rule_key: H256,
    pub ebc_rule_root: H256,
    pub ebc_rule_value: Vec<u8>,
    pub ebc_rule_merkle_proof: Vec<Bytes>,
    pub ebc_rule_pf_max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct StorageConstructor {
    pub block_number: u32,
    pub address: Address,
    pub slots: Vec<H256>,
    pub acct_pf_max_depth: usize,
    pub storage_pf_max_depth: usize,
    pub ebc_rule_params: EbcRuleParams,
    pub network: Network,
}

pub fn get_mdc_storage_circuit(constructor: StorageConstructor) -> EthBlockStorageCircuit {
    let mut addr = Default::default();
    let mdc_config = get_mdc_config();
    let provider = get_provider(&constructor.network);

    match &constructor.network {
        Network::Ethereum(EthereumNetwork::Mainnet) => {
            addr = mdc_config.mainnet;
        }
        Network::Ethereum(EthereumNetwork::Goerli) => {
            addr = mdc_config.goerli;
        }
        _ => {
            panic!("no match network Type! {:?}", &constructor.network)
        }
    }

    // ebc_rule_mpt
    let ebc_rule_key =
        H256::from_str("0x3c88efaf9c3d1286548d2deb92050254b42314cf32d32c85e8f641e116d445ac")
            .unwrap();
    let ebc_rule_root =
        H256::from_str("0xd5fe6597c1607bb7c648c8b50e605ff2cd84a52e3e5ecb1e6381dc29e5ee963b")
            .unwrap(); // should be consistent with the value corresponding to the slot
    let ebc_rule_value = Vec::from_hex("f83c058201a4010180808701c6bf52634c3587027ca57357c0198701c6bf526342718702d79883d23d09865af31082cb80865af3108626e00102211c1b1e").unwrap();

    let proof_one_bytes = Vec::from_hex("f851808080a054400bf453b955313a021e9e2c4ca85a8fc549642c13bd15743a74ccad8f6359808080808080808080a03df71b77eaaac25d64355678b33182a08f195c23a25eadafcc891c814bc3eda7808080").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);
    let proof_two_bytes = Vec::from_hex("f851808080808080a0b2848dbcfb2a125ed37d204fb2482d7584d52b2576e1a08a806c03963cd673bf8080808080a08af38922ea2dde162982a604c549b1a62eea1e524c22fcae14b5260204576d1c80808080").unwrap();
    let proof_two = Bytes::from(proof_two_bytes);
    let proof_three_bytes = Vec::from_hex("f861a02088efaf9c3d1286548d2deb92050254b42314cf32d32c85e8f641e116d445acb83ef83c058201a4010180808701c6bf52634c3587027ca57357c0198701c6bf526342718702d79883d23d09865af31082cb80865af3108626e00102211c1b1e").unwrap();
    let proof_three = Bytes::from(proof_three_bytes);

    let ebc_rule_merkle_proof = vec![proof_one, proof_two, proof_three];
    let ebc_rule_pf_max_depth = ebc_rule_merkle_proof.len().clone();

    let ebc_rule_params = EbcRuleParams {
        ebc_rule_key,
        ebc_rule_root,
        ebc_rule_value,
        ebc_rule_merkle_proof,
        ebc_rule_pf_max_depth,
    };

    // slots:
    addr = "0x3671625AD4CD14b6A4C2fb2697292E84DD3c1F10".parse().unwrap(); // for test
    let mapping_position = 0;
    let root_slot_position = 0;
    let version_slot_position = 1;

    let root_slot = calculate_mk_address_struct(addr, mapping_position, root_slot_position);
    let version_slot = calculate_mk_address_struct(addr, mapping_position, version_slot_position);
    let slots = vec![root_slot, version_slot];
    EthBlockStorageCircuit::from_provider(&provider, constructor)
}
