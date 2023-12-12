use clap::Parser;
use ethers_core::types::H256;
use log::{info, warn};
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task;
use zkspv_circuits::arbitration::router::SchedulerRouter;
use zkspv_circuits::config::log::init_log;
use zkspv_circuits::db::ChallengesStorage;
use zkspv_circuits::server::{init_server, OriginalProof};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long = "cache_srs_pk")]
    cache_srs_pk: bool,
    #[arg(long = "generate_smart_contract")]
    generate_smart_contract: bool,
}

#[tokio::main]
async fn main() {
    init_log();
    let args = Cli::parse();
    let scheduler = Arc::new(Mutex::new(SchedulerRouter::default()));
    let scheduler_cache_srs_pk = scheduler.clone();
    let scheduler_running = scheduler.clone();
    if args.cache_srs_pk {
        info!(target: "app","Start caching srs and pk files");
        task::spawn_blocking(move || {
            let arbitration_data_file =
                File::open("test_data/from_ethereum_to_zksync_era_source.json").unwrap();
            // let arbitration_data_file =
            //     File::open("test_data/from_ethereum_to_zksync_era_dest.json").unwrap();

            // let arbitration_data_file =
            //     File::open("test_data/from_zksync_era_to_ethereum_source.json").unwrap();

            // let arbitration_data_file =
            //     File::open("test_data/from_zksync_era_to_ethereum_dest.json").unwrap();

            let data_reader = BufReader::new(arbitration_data_file);
            let proof_str: Value = serde_json::from_reader(data_reader).unwrap();

            let op = OriginalProof { task_id: H256([0u8; 32]), proof: proof_str.to_string() };
            let constructor = op.clone().get_constructor_by_parse_proof();
            scheduler_cache_srs_pk.lock().unwrap().update(constructor, 1);
            scheduler_cache_srs_pk.lock().unwrap().cache_srs_pk_files();
        })
        .await
        .expect("cache srs pk should success");

        info!(target: "app","Caching of srs and pk files has ended");
    }

    let challenge_storage = Arc::new(Mutex::new(ChallengesStorage::new()));
    let (tx, mut rx) = mpsc::unbounded_channel::<OriginalProof>();

    let challenge_storage_clone = challenge_storage.clone();
    let receive_tasks = task::spawn(async move {
        init_server(tx, challenge_storage_clone).await.expect("init server error");
    });

    let execute_tasks = task::spawn(async move {
        while let original_proof = rx.recv().await {
            let scheduler_running = scheduler_running.clone();
            let challenge_storage_clone = challenge_storage.clone();
            let scheduler_result = task::spawn_blocking(move || {
                info!(target: "app","Start generating proof for Challenge: {:?}",original_proof.clone().unwrap().task_id);

                // clear
                let mut clear = Command::new("sh")
                    .arg("./scripts/clear_snark.sh")
                    .spawn()
                    .expect("Failed to execute command");
                let _ = clear.wait();
                let constructor = original_proof.clone().unwrap().get_constructor_by_parse_proof();
                scheduler_running.lock().unwrap().update(constructor, 1);
                (
                    original_proof.unwrap().task_id,
                    scheduler_running.lock().unwrap().get_calldata(args.generate_smart_contract),
                )
            })
            .await;
            match scheduler_result {
                Ok(result) => {
                    let storage = challenge_storage_clone.lock().unwrap();

                    let (challenge_id, proof) = result;
                    storage.storage_challenge_proof(challenge_id, proof).expect("save success");
                    info!(target: "app","Successfully generated proof for Challenge: {:?}",challenge_id);

                    println!("prove success")
                }
                Err(err) => {
                    warn!(target: "app","Failed to generate proof for Challenge,err: {}",err);
                    eprintln!("prove error: {}", err)
                }
            }
        }
    });

    tokio::join!(receive_tasks, execute_tasks);
}
