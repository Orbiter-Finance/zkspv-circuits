use ethers_core::types::H256;
use log::info;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task;
use zkspv_circuits::arbitration::router::ProofRouter;
use zkspv_circuits::db::ChallengesStorage;
use zkspv_circuits::server::{init_server, OriginalProof};

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("start services");
    let challenge_storage = Arc::new(Mutex::new(ChallengesStorage::new()));
    let (tx, mut rx) = mpsc::unbounded_channel::<OriginalProof>();

    let challenge_storage_clone = challenge_storage.clone();
    let receive_tasks = task::spawn(async move {
        init_server(tx, challenge_storage_clone).await.expect("init server error");
    });

    let execute_tasks = task::spawn(async move {
        while let original_proof = rx.recv().await {
            let challenge_storage_clone = challenge_storage.clone();
            // thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: JoinError::Panic(Id(264), ...)', src/bin/services.rs:30:14
            let mut a = task::spawn_blocking(|| {
                let constructor = original_proof.clone().unwrap().get_constructor_by_parse_proof();
                let task = ProofRouter::new(constructor, 1);
                (original_proof.unwrap().task_id, task.get_calldata(true))
            })
            .await;
            match a {
                Ok(result) => {
                    let mut storage = challenge_storage_clone.lock().unwrap();

                    let (challenge_id, proof) = result;
                    storage.storage_challenge_proof(challenge_id, proof).expect("save success");
                    println!("prove success")
                }
                Err(err) => eprintln!("prove error: {}", err),
            }
        }
    });

    tokio::join!(receive_tasks, execute_tasks);
}
