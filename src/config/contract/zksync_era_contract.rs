use ethers_core::types::{Address, H256};
use crate::config::load::get_contract_config;

pub fn get_zksync_era_nonce_holder_contract_address() ->Address{
    get_contract_config().zksync_era.nonce_holder.address
}

pub fn get_zksync_era_nonce_holder_contract_layout()->H256{
    get_contract_config().zksync_era.nonce_holder.layout
}