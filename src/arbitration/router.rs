use crate::arbitration::helper::ArbitrationTask::Final;
use crate::arbitration::helper::FinalAssemblyTask;
use crate::arbitration::types::ProofRouterConstructor;
use crate::util::scheduler::arbitration_scheduler::ArbitrationScheduler;
use crate::util::scheduler::Scheduler;
use crate::Network;
use ark_std::{end_timer, start_timer};
use itertools::Itertools;
use std::path::PathBuf;

fn init_scheduler(network: Network) -> ArbitrationScheduler {
    ArbitrationScheduler::new(
        network,
        false,
        false,
        PathBuf::from("configs/arbitration/"),
        PathBuf::from("data/arbitration/"),
        PathBuf::from("cache_data/arbitration/"),
    )
}

pub struct ProofRouter {
    pub arbitration_scheduler: ArbitrationScheduler,
    pub task: FinalAssemblyTask,
}

impl ProofRouter {
    pub fn new(constructor: ProofRouterConstructor, round: usize) -> Self {
        let task = constructor.proof.get_final_task(round);
        let scheduler = init_scheduler(task.from_network);
        ProofRouter { arbitration_scheduler: scheduler, task }
    }
    pub fn get_calldata(&self, generate_smart_contract: bool) -> String {
        let cache_time = start_timer!(|| "Cache srs pk files time");
        self.arbitration_scheduler.cache_srs_pk_files(Final(self.task.clone()));
        end_timer!(cache_time);
        let real_proof_time = start_timer!(|| "Real Proof time");
        let calldata = self
            .arbitration_scheduler
            .get_calldata(Final(self.task.clone()), generate_smart_contract);
        end_timer!(real_proof_time);
        calldata
    }
}

//pub fn get_transaction_constructor(){}
