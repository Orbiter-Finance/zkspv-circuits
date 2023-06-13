use std::str::FromStr;
use dotenv::dotenv;
use envy::from_env;
use ethers_core::types::{Address, H160, H256};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Config{
    pub mainnet_rpc:String,
    pub goerli_rpc:String,
    pub arbitrum_mainnet_rpc:String,
    pub arbitrum_goerli_rpc:String,
    pub optimism_mainnet_rpc:String,
    pub optimism_goerli_rpc:String,
    pub zksync_mainnet_rpc:String,
    pub zksync_goerli_rpc:String,
    pub zksync_nonce_holder:String,
    pub zksync_eth_address:String,
    pub zksync_usdc_address:String,
    pub zksync_weth_address:String,
    pub zksync_nonce_holder_layout:String,
    pub zksync_eth_address_layout:String,
    pub zksync_usdc_address_layout:String,
}

#[derive( Debug)]
pub struct TokenParams{
    pub address:Address,
    pub layout:H256
}

#[derive( Debug)]
pub struct ZkSyncEraToken{
    pub eth:TokenParams,
    pub usdc:TokenParams
}

#[derive( Debug)]
pub struct TokenConfig {
    pub zksync_era:ZkSyncEraToken
}

fn load_config() -> Config {
    dotenv().expect("Failed to read .env file");
    let mut configs = Config {
        mainnet_rpc: "".to_string(),
        goerli_rpc: "".to_string(),
        arbitrum_mainnet_rpc: "".to_string(),
        arbitrum_goerli_rpc: "".to_string(),
        optimism_mainnet_rpc: "".to_string(),
        optimism_goerli_rpc: "".to_string(),
        zksync_mainnet_rpc: "".to_string(),
        zksync_goerli_rpc: "".to_string(),
        zksync_nonce_holder: "".to_string(),
        zksync_eth_address: "".to_string(),
        zksync_usdc_address: "".to_string(),
        zksync_weth_address: "".to_string(),
        zksync_nonce_holder_layout: "".to_string(),
        zksync_eth_address_layout: "".to_string(),
        zksync_usdc_address_layout: "".to_string(),
    };
    match from_env::<Config>() {
        Ok(config) => configs = config,
        Err(e) => println!("Couldn't read mailer config ({})", e),
    }
    configs
}

pub fn get_token_config()->TokenConfig{
    let config =  load_config();
    TokenConfig{
        zksync_era: ZkSyncEraToken {
            eth: TokenParams {
                address:H160::from_str(config.zksync_eth_address.as_str()).unwrap(),
                layout: H256::from_low_u64_be(u64::from_str(config.zksync_eth_address_layout.as_str()).unwrap()),
            },
            usdc: TokenParams {
                address: H160::from_str(config.zksync_usdc_address.as_str()).unwrap(),
                layout: H256::from_low_u64_be(u64::from_str(config.zksync_usdc_address_layout.as_str()).unwrap())
            },
        },
    }
}

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
    let config =  load_config();
    ContractConfig{
        zksync_era: ZkSyncEraContract {
            nonce_holder: ContractParams {
                address: H160::from_str(config.zksync_nonce_holder.as_str()).unwrap(),
                layout: H256::from_low_u64_be(u64::from_str(config.zksync_nonce_holder_layout.as_str()).unwrap()),
            },
        },
    }
}