use std::path::Path;

use serde::{Serialize, Deserialize};

use crate::{util::{scheduler, EthConfigPinning, Halo2ConfigPinning}, transaction::ethereum::helper::TransactionTask, Network};


pub type CrossChainNetwork = Network;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalAssemblyTask {

}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ArbitrationTask {
    Transaction(),
    MDCState(),
    ETHBlockHeaderTrack(),
    Final(FinalAssemblyTask)
}

impl scheduler::CircuitType for (CrossChainNetwork,) {
    fn name(&self) -> String {
        format!("{}", self.0)
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        let pinning_path = pinning_path.as_ref();
        let pinning = EthConfigPinning::from_path(pinning_path);
        pinning.degree()
    }
}

// impl scheduler::Task for ArbitrationTask {
//     type CircuitType = (CrossChainNetwork,);

//     fn circuit_type(&self) -> Self::CircuitType {
//         (self.transaction_task.network as CrossChainNetwork, )
//     }

//     fn name(&self) -> String {
//         format!("{}", self.circuit_type().name())
//     }

//     fn dependencies(&self) -> Vec<Self> {
//         vec![
            
//         ]
//     }
// }