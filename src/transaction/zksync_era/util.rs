use crate::Network;
use ethers_core::types::H256;

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionConstructor {
    pub transaction_hash: H256,
    pub network: Network,
}
