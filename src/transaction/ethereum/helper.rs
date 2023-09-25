use super::EthBlockTransactionCircuit;
use crate::util::helpers::get_provider;
use crate::util::scheduler::evm_wrapper::{EvmWrapper, SimpleTask};
use crate::util::scheduler::{CircuitType, Task};
use crate::{
    util::{scheduler::Scheduler, EthConfigPinning, Halo2ConfigPinning},
    Network,
};
use ethers_core::types::{Bytes, H256};
use ethers_core::utils::keccak256;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use std::{env::var, path::Path, vec};

pub type TransactionScheduler = EvmWrapper<TransactionTask>;

#[derive(Clone, Debug)]
pub struct TransactionTask {
    pub block_number: u32,
    pub transaction_index: u32,
    pub transaction_rlp: Vec<u8>,
    pub merkle_proof: Vec<Bytes>,
    pub transaction_pf_max_depth: usize,
    pub network: Network,
}

impl TransactionTask {
    pub fn new(
        block_number: u32,
        transaction_index: u32,
        transaction_rlp: Vec<u8>,
        merkle_proof: Vec<Bytes>,
        transaction_pf_max_depth: usize,
        network: Network,
    ) -> Self {
        Self {
            block_number,
            transaction_index,
            transaction_rlp,
            merkle_proof,
            transaction_pf_max_depth,
            network,
        }
    }
    pub fn digest(&self) -> H256 {
        H256(keccak256(bincode::serialize(&self.transaction_rlp).unwrap()))
    }
}

impl CircuitType for (Network, u32) {
    fn name(&self) -> String {
        format!("{}_{}", self.0, self.1)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        let pinning_path = pinning_path.as_ref();
        let pinning = EthConfigPinning::from_path(pinning_path);
        pinning.degree()
    }
}

impl Task for TransactionTask {
    type CircuitType = (Network, u32);

    fn circuit_type(&self) -> Self::CircuitType {
        (self.network, self.transaction_index)
    }
    fn name(&self) -> String {
        format!("{}_{:?}", self.circuit_type().name(), self.digest())
    }
    fn dependencies(&self) -> Vec<Self> {
        vec![]
    }
}

impl SimpleTask for TransactionTask {
    type PreCircuit = EthBlockTransactionCircuit;

    fn get_circuit(&self, network: Network) -> Self::PreCircuit {
        let provider = get_provider(&network);
        EthBlockTransactionCircuit::from_provider(
            &provider,
            self.block_number,
            self.transaction_index,
            self.transaction_rlp.clone(),
            self.merkle_proof.clone(),
            self.transaction_pf_max_depth,
            self.network,
        )
    }
}
