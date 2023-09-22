use std::path::Path;

use crate::{util::{scheduler, EthConfigPinning, Halo2ConfigPinning}, Network};



#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthTrackBlockCircuitType {
    pub network: Network,
    pub tasks_len: u64,
    pub task_width: u64,
}

impl scheduler::CircuitType for EthTrackBlockCircuitType {
    fn name(&self) -> String {
        format!("blockTrack_width_{}",self.task_width)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        EthConfigPinning::from_path(pinning_path.as_ref()).degree()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum ArbitrationCircuitType {
    TrackBlock(EthTrackBlockCircuitType)
}

impl scheduler::CircuitType for ArbitrationCircuitType {
    
    fn name(&self) -> String {
        match self {
            ArbitrationCircuitType::TrackBlock(circuit_type) => {
                circuit_type.name()
            }
        }
    }

    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        match self {
            ArbitrationCircuitType::TrackBlock(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }
        }
    }
}