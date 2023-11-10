use crate::transaction::ethereum::EthBlockTransactionCircuit;
use crate::util::helpers::get_provider;
use crate::Network;
use ethers_core::types::Bytes;

#[derive(Clone, Debug)]
pub struct TransactionConstructor {
    pub block_number: u32,
    pub transaction_index: Option<u32>,
    pub transaction_index_bytes: Option<Vec<u8>>,
    pub transaction_rlp: Vec<u8>,
    pub merkle_proof: Vec<Bytes>,
    pub transaction_pf_max_depth: usize,
    pub network: Network,
}

pub fn get_eth_transaction_circuit(
    constructor: TransactionConstructor,
) -> EthBlockTransactionCircuit {
    let provider = get_provider(&constructor.network);

    EthBlockTransactionCircuit::from_provider(&provider, constructor)
}
