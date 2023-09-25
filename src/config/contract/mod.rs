pub mod zksync_era_contract;

use crate::config::setting::Settings;
use ethers_core::types::{Address, H160, H256};
use std::str::FromStr;

#[derive(Debug)]
pub struct MDCConfig {
    pub mainnet: Address,
    pub goerli: Address,
}

pub fn get_mdc_config() -> MDCConfig {
    let setting = Settings::get();
    MDCConfig {
        mainnet: H160::from_str(setting.mdc_config.mainnet.as_str()).unwrap(),
        goerli: H160::from_str(setting.mdc_config.goerli.as_str()).unwrap(),
    }
}

#[derive(Debug)]
pub struct ContractParams {
    pub address: Address,
    pub layout: H256,
}

#[derive(Debug)]
pub struct ZkSyncEraContract {
    pub nonce_holder: ContractParams,
}

#[derive(Debug)]
pub struct ContractConfig {
    pub zksync_era: ZkSyncEraContract,
}

pub fn get_contract_config() -> ContractConfig {
    let setting = Settings::get();
    ContractConfig {
        zksync_era: ZkSyncEraContract {
            nonce_holder: ContractParams {
                address: H160::from_str(setting.contracts.zksync_nonce_holder.as_str()).unwrap(),
                layout: H256::from_low_u64_be(setting.layout.zksync_nonce_holder),
            },
        },
    }
}
