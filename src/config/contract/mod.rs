pub mod zksync_era_contract;

use std::str::FromStr;
use ethers_core::types::{Address, H160, H256};
use crate::config::setting::Settings;

#[derive( Debug)]
pub struct ContractParams{
    pub address:Address,
    pub layout:H256
}

#[derive( Debug)]
pub struct ZkSyncEraContract{
    pub nonce_holder:ContractParams
}

#[derive( Debug)]
pub struct ContractConfig{
    pub zksync_era:ZkSyncEraContract
}

pub fn get_contract_config()->ContractConfig{
    let setting = Settings::get();
    ContractConfig{
        zksync_era: ZkSyncEraContract {
            nonce_holder: ContractParams {
                address: H160::from_str(setting.contracts.zksync_nonce_holder.as_str()).unwrap(),
                layout: H256::from_low_u64_be(setting.layout.zksync_nonce_holder),
            },
        },
    }
}