use crate::util::helpers::get_provider;
use crate::{Network, ZkSyncEraNetwork};
use ethers_providers::Middleware;
use tokio::runtime::Runtime;

#[test]
fn test_p() {
    let network = Network::ZkSync(ZkSyncEraNetwork::Mainnet);
    let provider = get_provider(&network);
    let rt = Runtime::new().unwrap();
    let block_element = rt.block_on(provider.get_block(18606590)).unwrap().unwrap();
    println!("{:?}", block_element);
}
