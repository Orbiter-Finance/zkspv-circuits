use crate::arbitration::helper::ArbitrationTask::Final;
use crate::arbitration::helper::FinalAssemblyTask;
use crate::arbitration::types::SchedulerRouterConstructor;
use crate::util::helpers::get_provider;
use crate::util::scheduler::arbitration_scheduler::ArbitrationScheduler;
use crate::util::scheduler::Scheduler;
use crate::Network;
use ark_std::{end_timer, start_timer};
use itertools::Itertools;
use std::path::PathBuf;
use std::sync::Arc;

pub struct SchedulerRouter {
    pub arbitration_scheduler: Option<ArbitrationScheduler>,
    pub task: Option<FinalAssemblyTask>,
}

impl SchedulerRouter {
    pub fn new(constructor: SchedulerRouterConstructor, round: usize) -> Self {
        let task = constructor.proof.get_final_task(round);
        let arbitration_scheduler = ArbitrationScheduler::default(task.from_network);
        SchedulerRouter { arbitration_scheduler: Some(arbitration_scheduler), task: Some(task) }
    }

    pub fn default() -> Self {
        Self { arbitration_scheduler: None, task: None }
    }

    pub fn update(&mut self, constructor: SchedulerRouterConstructor, round: usize) {
        let task = constructor.proof.get_final_task(round);
        if let Some(arbitration_scheduler) = self.arbitration_scheduler.as_mut() {
            arbitration_scheduler.network = task.from_network;
            arbitration_scheduler.provider = Arc::from(get_provider(&task.from_network));
        } else {
            self.arbitration_scheduler = Some(ArbitrationScheduler::default(task.from_network));
        }
        self.task = Some(task);
    }

    pub fn cache_srs_pk_files(&self) {
        let cache_time = start_timer!(|| "Cache srs pk files time");
        self.arbitration_scheduler
            .as_ref()
            .unwrap()
            .cache_srs_pk_files(Final(self.task.clone().unwrap()));
        end_timer!(cache_time);
    }

    pub fn get_calldata(&self, generate_smart_contract: bool) -> String {
        let real_proof_time = start_timer!(|| "Real Proof time");
        let calldata = self
            .arbitration_scheduler
            .as_ref()
            .unwrap()
            .get_calldata(Final(self.task.clone().unwrap()), generate_smart_contract);
        end_timer!(real_proof_time);
        calldata
    }
}
