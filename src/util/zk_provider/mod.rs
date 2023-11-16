use crate::util::helpers::get_provider;
use crate::{Network, ZkSyncEraNetwork};
use ethers_core::types::H256;
use ethers_providers::Middleware;
use std::str::FromStr;
use tokio::runtime::Runtime;
use zksync_web3_rs::zks_provider::ZKSProvider;

#[test]
fn test_p() {
    let network = Network::ZkSync(ZkSyncEraNetwork::Mainnet);
    let provider = get_provider(&network);
    let rt = Runtime::new().unwrap();
    let block_element = rt.block_on(provider.get_block(18606590)).unwrap().unwrap();
    println!("{:?}", block_element);
}

// Todo:zksync tx  eip1559 is support ecdsa chip,but then 2718? 2930? or other?
#[test]
fn test_transaction_rlp() {
    let network = Network::ZkSync(ZkSyncEraNetwork::Mainnet);
    let provider = get_provider(&network);
    let rt = Runtime::new().unwrap();
    let tx = H256::from_str("0x43793e2d74822b85f88eb9b2fcd771dc2a85e50091f2e2b0536fb2c796d31c5e")
        .unwrap();
    let block_element = rt.block_on(provider.get_transaction(tx)).unwrap().unwrap();
    println!("{:?}", block_element.recover_from());
}
