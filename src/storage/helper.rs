use std::path::Path;

use crate::util::scheduler::{CircuitType, Task};
use crate::util::{EthConfigPinning, Halo2ConfigPinning};
use crate::Network;

pub type StorageBlockRange = [u32; 3];

pub enum StorageTask {
    SingleStorage(SingleStorageTask),
    BatchStorage(BatchStorageTask),
}

pub struct SingleStorageTask {
    pub network: Network,
    pub block_num: u32,
}

// impl CircuitType for (Network, u32) {
//     fn name(&self) -> String {
//         format!("single_storage_{}_{}", self.0, self.1)
//     }

//     fn get_degree_from_pinning(&self, path: impl AsRef<Path>) -> u32 {
//         let pinning_path = path.as_ref();
//         let pinning = EthConfigPinning::from_path(pinning_path);
//         pinning.degree()
//     }
// }

// impl Task for SingleStorageTask {
//     type CircuitType = (Network, u32);

//     fn circuit_type(&self) -> Self::CircuitType {
//         (self.network, self.block_num)
//     }
//     fn name(&self) -> String {
//         format!("{}", self.circuit_type().name())
//     }
//     fn dependencies(&self) -> Vec<Self> {
//         vec![]
//     }
// }

#[derive(Clone, Debug)]
pub struct BatchStorageTask {
    pub network: Network,
    pub block_range: StorageBlockRange,
}

impl BatchStorageTask {
    pub fn new(network: Network, block_range: StorageBlockRange) -> Self {
        Self { network, block_range }
    }
}

impl CircuitType for (Network, u32, u32, u32) {
    fn name(&self) -> String {
        format!("{}_{}_{}_{}", self.0, self.1, self.2, self.3)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        let pinning_path = pinning_path.as_ref();
        let pinning = EthConfigPinning::from_path(pinning_path);
        pinning.degree()
    }
}

impl Task for BatchStorageTask {
    type CircuitType = (Network, u32, u32, u32);

    fn circuit_type(&self) -> Self::CircuitType {
        (self.network, self.block_range[0], self.block_range[1], self.block_range[2])
    }
    fn name(&self) -> String {
        format!("{}", self.circuit_type().name())
    }
    fn dependencies(&self) -> Vec<Self> {
        vec![
            // StorageTask::SingleStorage(SingleStorageTask { network: self.network, block_num: self.block_range[0] }),
            // StorageTask::SingleStorage(SingleStorageTask { network: self.network, block_num: self.block_range[1] }),
            // StorageTask::SingleStorage(SingleStorageTask { network: self.network, block_num: self.block_range[2] })
        ]
    }
}
