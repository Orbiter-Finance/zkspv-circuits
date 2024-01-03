use crate::arbitration::router::SchedulerRouter;
use crate::db::ChallengesStorage;
use crate::server::OriginalProof;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub struct Integration {
    pub scheduler: Arc<Mutex<SchedulerRouter>>,
    pub storage: Arc<Mutex<ChallengesStorage>>,
    pub mpsc: (UnboundedSender<OriginalProof>, UnboundedReceiver<OriginalProof>),
}

impl Integration {
    pub fn new() -> Self {
        let scheduler = Arc::new(Mutex::new(SchedulerRouter::default()));
        let storage = Arc::new(Mutex::new(ChallengesStorage::new()));
        let mpsc = mpsc::unbounded_channel::<OriginalProof>();
        Self { scheduler, storage, mpsc }
    }
}
