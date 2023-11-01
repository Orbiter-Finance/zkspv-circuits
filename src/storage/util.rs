use crate::{util::helpers::get_provider, Network};
use ethers_core::types::H256;
use ethers_core::types::{Address, Bytes};

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
    let provider = get_provider(&constructor.network);
    EthBlockStorageCircuit::from_provider(&provider, constructor)
}
