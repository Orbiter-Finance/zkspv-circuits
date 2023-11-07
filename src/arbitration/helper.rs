use ethers_core::types::{Bytes, H256};
use ethers_core::utils::keccak256;

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::arbitration::circuit_types::{
    EthStorageCircuitType, EthTransactionCircuitType, FinalAssemblyCircuitType,
};
use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::storage::contract_storage::util::{
    get_contracts_storage_circuit, MultiBlocksContractsStorageConstructor,
};
use crate::storage::contract_storage::ObContractsStorageCircuit;
use crate::track_block::util::TrackBlockConstructor;
use crate::transaction::ethereum::util::{get_eth_transaction_circuit, TransactionConstructor};
use crate::transaction::EthTransactionType;
use crate::util::scheduler::CircuitType;
use crate::{
    track_block::{util::get_eth_track_block_circuit, EthTrackBlockCircuit},
    transaction::ethereum::EthBlockTransactionCircuit,
    util::{scheduler, EthConfigPinning, Halo2ConfigPinning},
    EthereumNetwork, Network,
};

use super::circuit_types::{ArbitrationCircuitType, EthTrackBlockCircuitType};

pub type CrossChainNetwork = Network;

#[derive(Clone, Debug)]
pub struct ETHBlockTrackTask {
    pub input: EthTrackBlockCircuit,
    pub network: Network,
    pub tasks_len: u64,  // Group number of blocks
    pub task_width: u64, // Length of a group of blocks
    pub constructor: Vec<TrackBlockConstructor>,
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
        if self.circuit_type().is_aggregated() {
            format!(
                "block_track_aggregated_width_{}_task_len_{}",
                self.task_width,
                self.constructor.len()
            )
        } else {
            format!(
                "block_track_width_{}_start_{}_end_{}",
                self.task_width,
                self.constructor[0].blocks_number.first().unwrap(),
                self.constructor[0].blocks_number.last().unwrap()
            )
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructors = self.constructor.clone();
            let result = constructors
                .into_iter()
                .map(|constructor| Self {
                    input: get_eth_track_block_circuit(constructor.clone()),
                    network: self.network,
                    tasks_len: 1u64,
                    task_width: self.task_width,
                    constructor: [constructor].to_vec(),
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

/// Transaction
#[derive(Clone, Debug)]
pub struct TransactionTask {
    pub input: EthBlockTransactionCircuit,
    pub tx_type: EthTransactionType,
    pub tasks_len: u64,
    pub constructor: Vec<TransactionConstructor>,
    pub aggregated: bool,
}

impl TransactionTask {
    fn hash(&self) -> H256 {
        H256(keccak256(bincode::serialize(&self.constructor[0].transaction_rlp).unwrap()))
    }
}

impl scheduler::Task for TransactionTask {
    type CircuitType = EthTransactionCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthTransactionCircuitType {
            network: self.constructor[0].network,
            tx_type: self.tx_type.clone(),
            tasks_len: self.tasks_len,
            aggregated: self.aggregated,
        }
    }

    fn name(&self) -> String {
        if self.circuit_type().is_aggregated() {
            format!(
                "transaction_aggregated_{}_task_len_{}",
                self.tx_type.to_string(),
                self.tasks_len
            )
        } else {
            format!("transaction_{}_tx_{}", self.tx_type.to_string(), self.hash())
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructor = self.constructor.clone();
            let result = constructor
                .into_iter()
                .map(|constructor| Self {
                    input: get_eth_transaction_circuit(constructor.clone()),
                    tx_type: self.tx_type.clone(),
                    tasks_len: 1u64,
                    constructor: [constructor].to_vec(),
                    aggregated: false,
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum TransactionInput {
    EthereumTx(),
}

#[derive(Clone, Debug)]
pub struct MDCStateTask {
    pub input: ObContractsStorageCircuit,
    pub single_block_include_contracts: u64,
    pub multi_blocks_number: u64,
    pub constructor: Vec<MultiBlocksContractsStorageConstructor>,
    pub aggregated: bool,
}

impl scheduler::Task for MDCStateTask {
    type CircuitType = EthStorageCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthStorageCircuitType {
            network: self.constructor[0].network,
            single_block_include_contracts: self.single_block_include_contracts,
            multi_blocks_number: self.multi_blocks_number,
            aggregated: self.aggregated,
        }
    }

    fn name(&self) -> String {
        self.circuit_type().name()
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructor = self.constructor.clone();
            let result = constructor
                .into_iter()
                .map(|constructor| Self {
                    input: get_contracts_storage_circuit(constructor.clone()),
                    single_block_include_contracts: self.single_block_include_contracts,
                    multi_blocks_number: self.multi_blocks_number,
                    constructor: [constructor].to_vec(),
                    aggregated: self.aggregated,
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

#[derive(Clone, Debug)]
pub struct FinalAssemblyConstructor {
    pub transaction_task: Option<TransactionTask>,
    pub eth_block_track_task: Option<ETHBlockTrackTask>,
    pub mdc_state_task: Option<Vec<MDCStateTask>>,
}

#[derive(Clone, Debug)]
pub struct FinalAssemblyTask {
    pub round: usize,
    pub aggregation_type: FinalAssemblyType,
    pub network: Network,
    pub constructor: FinalAssemblyConstructor,
}

impl scheduler::Task for FinalAssemblyTask {
    type CircuitType = FinalAssemblyCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        FinalAssemblyCircuitType {
            round: self.round,
            aggregation_type: self.aggregation_type.clone(),
            network: self.network,
        }
    }

    fn name(&self) -> String {
        self.circuit_type().name()
    }

    fn dependencies(&self) -> Vec<Self> {
        vec![]
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
            ArbitrationTask::Final(task) => {
                ArbitrationCircuitType::FinalAssembly(task.circuit_type())
            }
        }
    }

    fn name(&self) -> String {
        match self {
            ArbitrationTask::ETHBlockTrack(task) => task.name(),
            ArbitrationTask::Transaction(task) => task.name(),
            ArbitrationTask::MDCState(task) => task.name(),
            ArbitrationTask::Final(task) => task.name(),
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
            ArbitrationTask::Final(task) => {
                if task.circuit_type().round != 0 {
                    let mut circuit_type = task.circuit_type().clone();
                    circuit_type.round -= 1;
                    return vec![ArbitrationTask::Final(FinalAssemblyTask {
                        round: circuit_type.round,
                        ..task.clone()
                    })];
                }
                let task = task.clone();
                match task.aggregation_type {
                    FinalAssemblyType::Source => {
                        let mut task_array = vec![];
                        task_array.push(ArbitrationTask::Transaction(
                            task.constructor.transaction_task.unwrap(),
                        ));
                        task_array.push(ArbitrationTask::ETHBlockTrack(
                            task.constructor.eth_block_track_task.unwrap(),
                        ));
                        let mut mdc_state_tasks = task
                            .constructor
                            .mdc_state_task
                            .unwrap()
                            .iter()
                            .map(|mdc_state| ArbitrationTask::MDCState(mdc_state.clone()))
                            .collect_vec();
                        task_array.append(&mut mdc_state_tasks);
                        task_array
                    }
                    FinalAssemblyType::Destination => {
                        vec![
                            ArbitrationTask::Transaction(
                                task.constructor.transaction_task.unwrap(),
                            ),
                            ArbitrationTask::ETHBlockTrack(
                                task.constructor.eth_block_track_task.unwrap(),
                            ),
                        ]
                    }
                }
            }
        }
    }
}
