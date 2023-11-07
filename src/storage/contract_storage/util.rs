use crate::storage::contract_storage::ObContractsStorageCircuit;
use crate::util::helpers::get_provider;
use crate::Network;
use ethers_core::types::{Address, Bytes, H256};

#[derive(Clone, Debug)]
pub struct EbcRuleParams {
    pub ebc_rule_key: H256,
    pub ebc_rule_root: H256,
    pub ebc_rule_value: Vec<u8>,
    pub ebc_rule_merkle_proof: Vec<Bytes>,
    pub ebc_rule_pf_max_depth: usize,
}

/**
 - contract_address is mdc、manage
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
pub struct SingleBlockContractStorageConstructor {
    pub contract_address: Address,
    pub slots: Vec<H256>,
    pub acct_pf_max_depth: usize,
    pub storage_pf_max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct SingleBlockContractsStorageConstructor {
    pub block_number: u32,
    pub block_contracts_storage: Vec<SingleBlockContractStorageConstructor>,
    pub ebc_rule_params: EbcRuleParams,
}

#[derive(Clone, Debug)]
pub struct MultiBlocksContractsStorageConstructor {
    pub blocks_contracts_storage: Vec<SingleBlockContractsStorageConstructor>,
    pub network: Network,
}

pub fn get_contracts_storage_circuit(
    constructor: MultiBlocksContractsStorageConstructor,
) -> ObContractsStorageCircuit {
    let provider = get_provider(&constructor.network);
    ObContractsStorageCircuit::from_provider(&provider, constructor)
}
