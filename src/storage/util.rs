use crate::{util::helpers::get_provider, Network};
use ethers_core::types::H256;
use ethers_core::types::{Address, Bytes};

use super::EthBlockStorageCircuit;

#[derive(Clone, Debug)]
pub struct StorageConstructor {
    pub block_number: u32,
    pub address: Address,
    pub slots: Vec<H256>,
    pub acct_pf_max_depth: usize,
    pub storage_pf_max_depth: usize,
    pub network: Network,
}

pub fn get_mdc_storage_circuit(constructor: StorageConstructor) -> EthBlockStorageCircuit {
    let provider = get_provider(&constructor.network);
    EthBlockStorageCircuit::from_provider(&provider, constructor)
}
