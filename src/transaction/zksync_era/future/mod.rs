use crate::mpt::AssignedBytes;
use crate::util::helpers::load_bytes;
use halo2_base::{AssignedValue, Context};
use zkevm_keccak::util::eth_types::Field;
use zksync_web3_rs::zks_provider::types::BlockDetails;

mod tests;

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionInput {
    pub transaction_status: u64,
    pub transaction_value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionInputAssigned<F: Field> {
    pub transaction_status: AssignedValue<F>,
    pub transaction_value: AssignedBytes<F>,
}

impl ZkSyncEraTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ZkSyncEraTransactionInputAssigned<F> {
        let transaction_status = (F::from(self.transaction_status)).try_into().unwrap();
        let transaction_status = ctx.load_witness(transaction_status);
        let transaction_value = load_bytes(ctx, self.transaction_value.as_slice());
        ZkSyncEraTransactionInputAssigned { transaction_status, transaction_value }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockTransactionInput {
    pub block: BlockDetails,
    // pub block_number: u32,
    // pub block_hash: H256,
    // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub transaction: ZkSyncEraTransactionInput,
}

// Todo 开发zksync区块头电路
#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockTransactionInputAssigned<F: Field> {
    pub block_header: Vec<u8>,
    pub transaction: ZkSyncEraTransactionInputAssigned<F>,
}
