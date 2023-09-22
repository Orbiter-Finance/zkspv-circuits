use std::{fmt::format, ops::Range, path::Path};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

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
pub struct MDCStateTask {}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum TransactionInput {
    EthereumTx(),
}

#[derive(Clone, Debug)]
pub struct TransactionTask {
    pub intput: TransactionInput,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum ArbitrationTask {
    Transaction(),
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
            ArbitrationTask::Transaction() => todo!(),
            ArbitrationTask::MDCState(task) => todo!(),
            ArbitrationTask::Final(task) => todo!(),
        }
    }

    fn name(&self) -> String {
        match self {
            ArbitrationTask::ETHBlockTrack(task) => task.name(),
            ArbitrationTask::Transaction() => todo!(),
            ArbitrationTask::MDCState(_) => todo!(),
            ArbitrationTask::Final(_) => todo!(),
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        match self {
            ArbitrationTask::Transaction() => todo!(),
            ArbitrationTask::MDCState(_) => todo!(),
            ArbitrationTask::ETHBlockTrack(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::ETHBlockTrack).collect()
            }
            ArbitrationTask::Final(_) => todo!(),
        }
    }
}
