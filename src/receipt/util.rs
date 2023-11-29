use crate::receipt::EthBlockReceiptCircuit;
use crate::util::helpers::get_provider;
use crate::Network;
use ethers_core::types::{Bytes, H256};

pub const RECEIPT_PF_MAX_DEPTH: usize = 6;
#[derive(Clone, Debug)]
pub struct ReceiptConstructor {
    pub transaction_hash: H256,
    pub receipt_index_bytes: Option<Vec<u8>>,
    pub receipt_rlp: Vec<u8>,
    pub merkle_proof: Vec<Bytes>,
    pub receipt_pf_max_depth: usize,
    pub network: Network,
}

impl ReceiptConstructor {
    pub fn new(
        transaction_hash: H256,
        receipt_index_bytes: Option<Vec<u8>>,
        receipt_rlp: Vec<u8>,
        merkle_proof: Vec<Bytes>,
        receipt_pf_max_depth: usize,
        network: Network,
    ) -> Self {
        Self {
            transaction_hash,
            receipt_index_bytes,
            receipt_rlp,
            merkle_proof,
            receipt_pf_max_depth,
            network,
        }
    }

    pub fn get_circuit(self) -> EthBlockReceiptCircuit {
        let provider = get_provider(&self.network);
        EthBlockReceiptCircuit::from_provider(&provider, self)
    }
}
