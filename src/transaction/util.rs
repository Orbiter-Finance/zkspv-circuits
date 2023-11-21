use crate::transaction::ethereum::EthBlockTransactionCircuit;
use crate::transaction::zksync_era::ZkSyncEraBlockTransactionCircuit;
use crate::util::errors::ErrorType;
use crate::util::helpers::get_provider;
use crate::Network;
use ethers_core::types::{Bytes, H256};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug)]
pub struct TransactionConstructor {
    pub transaction_hash: H256,
    pub transaction_index_bytes: Option<Vec<u8>>,
    pub transaction_rlp: Option<Vec<u8>>,
    pub merkle_proof: Option<Vec<Bytes>>,
    pub transaction_pf_max_depth: Option<usize>,
    pub network: Network,
}

// pub enum TransactionCircuitType {
//     EthBlockTransactionCircuit(EthBlockTransactionCircuit),
//     ZkSyncEraBlockTransactionCircuit(ZkSyncEraBlockTransactionCircuit),
// }
//
// pub trait CircuitType: Clone + Debug + Eq + Hash + Send + Sync {}
//
// pub trait TransactionCircuit: Clone + Debug + Sync + Send {
//     type CircuitType: CircuitType;
//     fn get_circuit(&self) -> Self::CircuitType;
// }
//
// impl CircuitType for EthBlockTransactionCircuit {}
//
// impl CircuitType for ZkSyncEraBlockTransactionCircuit {}
//
// #[allow(clippy::large_enum_variant)]
// #[derive(Clone, Debug)]
// pub enum TransactionCircuitTask {
//     EthTransaction(EthTransactionTask),
//     ZkSyncEraTransaction(ZkSyncEraTransactionTask),
// }
//
// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
// pub struct EthTransactionTask {
//     pub constructor: TransactionConstructor,
// }
//
// impl TransactionCircuit for EthTransactionTask {
//     type CircuitType = EthBlockTransactionCircuit;
//
//     fn get_circuit(&self) -> Self::CircuitType {
//         let provider = get_provider(&self.constructor.network);
//         EthBlockTransactionCircuit::from_provider(&provider, self.constructor.clone())
//     }
// }
//
// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
// pub struct ZkSyncEraTransactionTask {
//     pub constructor: TransactionConstructor,
// }
//
// impl TransactionCircuit for ZkSyncEraTransactionTask {
//     type CircuitType = ZkSyncEraBlockTransactionCircuit;
//
//     fn get_circuit(&self) -> Self::CircuitType {
//         let provider = get_provider(&self.constructor.network);
//         ZkSyncEraBlockTransactionCircuit::from_provider(&provider, self.constructor.clone())
//     }
// }
//
// impl TransactionCircuit for TransactionCircuitTask {
//     type CircuitType = TransactionCircuitType;
//
//     fn get_circuit(&self) -> Self::CircuitType {
//         match self {
//             TransactionCircuitTask::EthTransaction(task) => task.get_circuit(),
//             TransactionCircuitTask::ZkSyncEraTransaction(task) => task.get_circuit(),
//         }
//     }
// }
//
// impl TransactionConstructor {
//     pub fn get_circuit<T: TransactionCircuit>(&self) -> Result<T::CircuitType, ErrorType> {
//         match self.network {
//             Network::Ethereum(_) => Ok(TransactionCircuitType::EthBlockTransactionCircuit(
//                 EthBlockTransactionCircuit::get_circuit(self.clone()),
//             )),
//             Network::ZkSync(_) => Ok(TransactionCircuitType::ZkSyncEraBlockTransactionCircuit(
//                 ZkSyncEraBlockTransactionCircuit::get_circuit(self.clone()),
//             )),
//             _ => Err(ErrorType::NetworkNotSupported),
//         }
//     }
// }

pub fn get_eth_transaction_circuit(
    constructor: TransactionConstructor,
) -> EthBlockTransactionCircuit {
    let provider = get_provider(&constructor.network);
    EthBlockTransactionCircuit::from_provider(&provider, constructor)
}

pub fn get_zksync_transaction_circuit(
    constructor: TransactionConstructor,
) -> ZkSyncEraBlockTransactionCircuit {
    let provider = get_provider(&constructor.network);
    ZkSyncEraBlockTransactionCircuit::from_provider(&provider, constructor)
}
