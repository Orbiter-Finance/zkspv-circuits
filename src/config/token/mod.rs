pub mod zksync_era_token;

use crate::config::setting::Settings;
use ethers_core::types::{Address, H160, H256};
use std::str::FromStr;

#[derive(Debug)]
pub struct TokenParams {
    pub address: Address,
    pub layout: H256,
}

#[derive(Debug)]
pub struct ZkSyncEraToken {
    pub eth: TokenParams,
    pub usdc: TokenParams,
}

#[derive(Debug)]
pub struct TokenConfig {
    pub zksync_era: ZkSyncEraToken,
}

pub fn get_token_config() -> TokenConfig {
    let setting = Settings::get();
    TokenConfig {
        zksync_era: ZkSyncEraToken {
            eth: TokenParams {
                address: H160::from_str(setting.token.zksync_eth.as_str()).unwrap(),
                layout: H256::from_low_u64_be(setting.layout.zksync_eth),
            },
            usdc: TokenParams {
                address: H160::from_str(setting.token.zksync_usdc.as_str()).unwrap(),
                layout: H256::from_low_u64_be(setting.layout.zksync_usdc),
            },
        },
    }
}
