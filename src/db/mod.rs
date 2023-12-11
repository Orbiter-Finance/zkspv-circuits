use crate::config::db::get_rocks_db_path;
use ethers_core::types::H256;
use jsonrpsee::core::Serialize;
use rocksdb::{DBWithThreadMode, Error, Options, SingleThreaded, DB};
use serde::Deserialize;

pub struct ChallengesStorage {
    pub storage: DBWithThreadMode<SingleThreaded>,
}

impl ChallengesStorage {
    pub fn new() -> Self {
        let path = get_rocks_db_path();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        ChallengesStorage {
            storage: DB::open(&opts, path).expect("Initialize database should succeed"),
        }
    }

    pub fn storage_challenge_proof(&self, challenge_id: H256, proof: String) -> Result<(), Error> {
        self.storage.put(challenge_id.as_bytes(), proof.as_bytes())
    }

    pub fn get_proof_by_challenge_id(&self, challenge_id: H256) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get(challenge_id)
    }
}
