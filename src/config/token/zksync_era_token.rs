use ethers_core::types::{Address, H256};
use thiserror::Error;
use crate::config::token::get_token_config;

#[derive(Clone, Copy, Debug, Error)]
pub enum TokenError {
    #[error("this token is not supported")]
    NotSupportToken,
}

pub fn get_zksync_era_eth_address() ->Address{
    get_token_config().zksync_era.eth.address
}

pub fn get_zksync_era_token_layout_by_address(address:Address) -> Result<H256, TokenError> {
    let config = get_token_config().zksync_era;
    return if address.eq(&config.usdc.address.clone()) {
        Ok(config.usdc.layout)
    } else {
        Err(TokenError::NotSupportToken)
    }
}
