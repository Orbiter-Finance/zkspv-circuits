use ethers_core::types::{Bytes, H256};
use ethers_core::utils::keccak256;
use std::{fmt::format, ops::Range, path::Path};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::arbitration::circuit_types::{EthStorageCircuitType, EthTransactionCircuitType};
use crate::storage::util::{get_mdc_storage_circuit, StorageConstructor};
use crate::storage::EthBlockStorageCircuit;
use crate::transaction::ethereum::util::{get_eth_transaction_circuit, TransactionConstructor};
use crate::{
    track_block::{util::get_eth_track_block_circuit, EthTrackBlockCircuit},
    transaction::ethereum::{
        helper::TransactionTask as ETHTransactionTask, EthBlockTransactionCircuit,
    },
    util::{scheduler, EthConfigPinning, Halo2ConfigPinning},
    EthereumNetwork, Network,
};

use super::circuit_types::{ArbitrationCircuitType, EthTrackBlockCircuitType};

pub type CrossChainNetwork = Network;

#[derive(Clone, Debug)]
pub struct FinalAssemblyTask {}

#[derive(Clone, Debug)]
pub struct ETHBlockTrackTask {
    pub input: EthTrackBlockCircuit,
    pub network: Network,
    pub tasks_len: u64,
    pub task_width: u64,
    pub track_task_interval: Vec<Range<u64>>,
}

impl scheduler::Task for ETHBlockTrackTask {
    type CircuitType = EthTrackBlockCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthTrackBlockCircuitType {
            network: self.network,
            tasks_len: self.tasks_len,
            task_width: self.task_width,
        }
    }

    fn name(&self) -> String {
        format!(
            "blockTrack_width_{}_start_{}_end_{}",
            self.task_width, self.track_task_interval[0].start, self.track_task_interval[0].end
        )
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.tasks_len == 1 {
            return vec![];
        }
        let track_task_interval = self.track_task_interval.clone();
        let result = track_task_interval
            .into_iter()
            .map(|interval| {
                let d = interval.clone();
                Self {
                    input: get_eth_track_block_circuit(interval.collect_vec(), self.network),
                    network: self.network,
                    tasks_len: 1u64,
                    task_width: self.task_width,
                    track_task_interval: [d].to_vec(),
                }
            })
            .collect_vec();
        result
    }
}

#[derive(Clone, Debug)]
pub struct MDCStateTask {
    pub input: EthBlockStorageCircuit,
    pub tasks_len: u64,
    pub task_width: u64,
    pub constructor: Vec<StorageConstructor>,
}

impl scheduler::Task for MDCStateTask {
    type CircuitType = EthStorageCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthStorageCircuitType {
            network: self.constructor[0].network,
            tasks_len: self.tasks_len,
            task_width: self.task_width,
        }
    }

    fn name(&self) -> String {
        format!(
            "storage_width_{}_address_{}_slots_{}_block_number_{}",
            self.task_width,
            self.constructor[0].address,
            self.constructor[0].slots[0],
            self.constructor[0].block_number,
        )
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.tasks_len == 1 {
            return vec![];
        }
        let constructor = self.constructor.clone();
        let result = constructor
            .into_iter()
            .map(|constructor| Self {
                input: get_mdc_storage_circuit(constructor.clone()),
                tasks_len: 1u64,
                task_width: self.task_width,
                constructor: [constructor].to_vec(),
            })
            .collect_vec();
        result
    }
}

// #[allow(clippy::large_enum_variant)]
// #[derive(Clone, Debug)]
// pub enum TransactionInput {
//     EthBlockTransactionCircuit,
// }

#[derive(Clone, Debug)]
pub struct TransactionTask {
    pub input: EthBlockTransactionCircuit,
    pub tasks_len: u64,
    pub task_width: u64,
    pub constructor: Vec<TransactionConstructor>,
}

impl scheduler::Task for TransactionTask {
    type CircuitType = EthTransactionCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthTransactionCircuitType {
            network: self.constructor[0].network,
            tasks_len: self.tasks_len,
            task_width: self.task_width,
        }
    }

    fn name(&self) -> String {
        format!(
            "transaction_width_{}_tx_{}",
            self.task_width,
            H256(keccak256(bincode::serialize(&self.constructor[0].transaction_rlp).unwrap()))
        )
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.tasks_len == 1 {
            return vec![];
        }
        let constructor = self.constructor.clone();
        let result = constructor
            .into_iter()
            .map(|constructor| Self {
                input: get_eth_transaction_circuit(constructor.clone()),
                tasks_len: 1u64,
                task_width: self.task_width,
                constructor: [constructor].to_vec(),
            })
            .collect_vec();
        result
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum ArbitrationTask {
    Transaction(TransactionTask),
    MDCState(MDCStateTask),
    ETHBlockTrack(ETHBlockTrackTask),
    Final(FinalAssemblyTask),
}

impl scheduler::Task for ArbitrationTask {
    type CircuitType = ArbitrationCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        match self {
            ArbitrationTask::ETHBlockTrack(task) => {
                ArbitrationCircuitType::TrackBlock(task.circuit_type())
            }
            ArbitrationTask::Transaction(task) => {
                ArbitrationCircuitType::Transaction(task.circuit_type())
            }
            ArbitrationTask::MDCState(task) => {
                ArbitrationCircuitType::MdcStorage(task.circuit_type())
            }
            ArbitrationTask::Final(task) => todo!(),
        }
    }

    fn name(&self) -> String {
        match self {
            ArbitrationTask::ETHBlockTrack(task) => task.name(),
            ArbitrationTask::Transaction(task) => task.name(),
            ArbitrationTask::MDCState(task) => task.name(),
            ArbitrationTask::Final(_) => todo!(),
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        match self {
            ArbitrationTask::Transaction(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::Transaction).collect()
            }
            ArbitrationTask::MDCState(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::MDCState).collect()
            }
            ArbitrationTask::ETHBlockTrack(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::ETHBlockTrack).collect()
            }
            ArbitrationTask::Final(_) => todo!(),
        }
    }
}
