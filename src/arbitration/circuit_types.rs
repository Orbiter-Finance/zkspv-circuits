use std::path::Path;

use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::transaction::EthTransactionType;
use crate::util::AggregationConfigPinning;
use crate::{
    util::{scheduler, EthConfigPinning, Halo2ConfigPinning},
    Network,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthTrackBlockCircuitType {
    pub network: Network,
    pub tasks_len: u64,
    pub task_width: u64,
}

impl EthTrackBlockCircuitType {
    fn name(&self) -> String {
        if self.is_aggregated() {
            format!("block_track_aggregate_width_{}_task_len_{}", self.task_width, self.tasks_len)
        } else {
            format!("block_track_width_{}", self.task_width)
        }
    }
    pub(crate) fn is_aggregated(&self) -> bool {
        return self.tasks_len != 1;
    }
}

impl scheduler::CircuitType for EthTrackBlockCircuitType {
    fn name(&self) -> String {
        self.name()
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.is_aggregated() {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthTransactionCircuitType {
    pub network: Network,
    pub tx_type: EthTransactionType,
    pub tasks_len: u64,
    pub aggregated: bool,
}

impl EthTransactionCircuitType {
    pub fn is_aggregated(&self) -> bool {
        return self.aggregated;
    }
}

impl scheduler::CircuitType for EthTransactionCircuitType {
    fn name(&self) -> String {
        if self.is_aggregated() {
            format!(
                "transaction_aggregate_{}_tasks_len_{}",
                self.tx_type.to_string(),
                self.tasks_len
            )
        } else {
            format!("transaction_{}", self.tx_type.to_string())
        }
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.is_aggregated() {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

//Todo Replace the task_width with the appropriate parameters
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthStorageCircuitType {
    pub network: Network,
    pub tasks_len: u64,
    pub task_width: u64,
}

impl EthStorageCircuitType {
    pub(crate) fn is_aggregated(&self) -> bool {
        self.tasks_len != 1
    }
}

impl scheduler::CircuitType for EthStorageCircuitType {
    fn name(&self) -> String {
        if self.is_aggregated() {
            format!("storage_aggregate_tasks_len_{}", self.tasks_len)
        } else {
            format!("storage_width_{}", self.task_width)
        }
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.is_aggregated() {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FinalAssemblyFinality {
    None,
    Evm(usize),
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FinalAssemblyCircuitType {
    /// Performs `round` rounds of SNARK verification using `PublicAggregationCircuit` on the final circuit.
    /// This is used to reduce circuit size and final EVM verification gas costs.
    pub round: usize,
    pub aggregation_type: FinalAssemblyType,
    pub network: Network,
}

impl FinalAssemblyCircuitType {
    pub fn name(&self) -> String {
        format!("{}_final_{}", self.aggregation_type.to_string(), self.round)
    }
}

impl scheduler::CircuitType for FinalAssemblyCircuitType {
    fn name(&self) -> String {
        self.name()
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum ArbitrationCircuitType {
    TrackBlock(EthTrackBlockCircuitType),
    Transaction(EthTransactionCircuitType),
    MdcStorage(EthStorageCircuitType),
    FinalAssembly(FinalAssemblyCircuitType),
}

impl scheduler::CircuitType for ArbitrationCircuitType {
    fn name(&self) -> String {
        match self {
            ArbitrationCircuitType::TrackBlock(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::Transaction(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::MdcStorage(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::FinalAssembly(circuit_type) => circuit_type.name(),
        }
    }

    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        match self {
            ArbitrationCircuitType::TrackBlock(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }

            ArbitrationCircuitType::Transaction(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }

            ArbitrationCircuitType::MdcStorage(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }

            ArbitrationCircuitType::FinalAssembly(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }
        }
    }
}
