use std::path::Path;

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
    pub fn is_aggregated(&self) -> bool {
        return self.tasks_len != 1
    }
}

impl scheduler::CircuitType for EthTrackBlockCircuitType {
    fn name(&self) -> String {
        if self.is_aggregated() {
            format!("blockTrack_aggregate_width_{}", self.task_width)
        } else {
            format!("blockTrack_width_{}", self.task_width)
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
pub struct EthTransactionCircuitType {
    pub network: Network,
    pub tasks_len: u64,
    pub task_width: u64,
}

impl scheduler::CircuitType for EthTransactionCircuitType {
    fn name(&self) -> String {
        format!("transaction_width_{}", self.task_width)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        EthConfigPinning::from_path(pinning_path.as_ref()).degree()
    }
}

//Todo Replace the task_width with the appropriate parameters
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthStorageCircuitType {
    pub network: Network,
    pub tasks_len: u64,
    pub task_width: u64,
}

impl scheduler::CircuitType for EthStorageCircuitType {
    fn name(&self) -> String {
        format!("storage_width_{}", self.task_width)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        EthConfigPinning::from_path(pinning_path.as_ref()).degree()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FinalAssemblyCircuitType {
    /// Performs `round` rounds of SNARK verification using `PublicAggregationCircuit` on the final circuit.
    /// This is used to reduce circuit size and final EVM verification gas costs.
    pub network: Network,
    pub round: usize,
}

impl scheduler::CircuitType for FinalAssemblyCircuitType {
    fn name(&self) -> String {
        format!("final_round_{}", self.round)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.round == 0 {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
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
