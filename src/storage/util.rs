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

/**
 - address is mdc
 - slots is
    1. mdc_rule_config_root_hash_slot,
    2. mdc_rule_config_version_slot,
    3. mdc_rule_config_enable_time_slot,
    4. manage_source_chain_info_slot
    5. manage_source_chain_mainnet_token_info_slot,
    6. manage_dest_chain_mainnet_token_slot,
    7. manage_challenge_user_ratio_slot,
    8. manage_column_array_hash_slot,
    9. manage_response_makers_hash_slot,
 -  *manage_source_chain_info_slot* is
```solidity
uint64 minVerifyChallengeSourceTxSecond;
uint64 maxVerifyChallengeSourceTxSecond;
uint64 minVerifyChallengeDestTxSecond;
uint64 maxVerifyChallengeDestTxSecond;
```
*/
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
