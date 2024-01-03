use clap::Parser;
use ethers_core::types::H256;
use log::{info, warn};
use parking_lot::Mutex;
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::process::Command;
use std::sync::Arc;
use tokio::task;
use zkspv_circuits::config::log::init_log;
use zkspv_circuits::integration::Integration;
use zkspv_circuits::server::{init_server, OriginalProof};
use zkspv_circuits::util::cache::CacheConfig;

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
    let integration = Integration::new();
    if args.cache_srs_pk {
        info!(target: "app","Start caching srs and pk files");

        let scheduler_cache_srs_pk = integration.scheduler.clone();
        task::spawn_blocking(move || {
            let cache = CacheConfig::from_reader("configs/cache/cache.json");
            for path in cache.list {
                info!(target: "app","Start caching srs and pk files: {:?}",path);
                let arbitration_data_file = File::open(path.clone()).unwrap();
                let data_reader = BufReader::new(arbitration_data_file);
                let proof_str: Value = serde_json::from_reader(data_reader).unwrap();

                let op = OriginalProof { task_id: H256::zero(), proof: proof_str.to_string() };
                let constructor = op.clone().get_constructor_by_parse_proof();
                {
                    let mut scheduler = scheduler_cache_srs_pk.lock();
                    scheduler.update(constructor, 1);
                    scheduler.cache_srs_pk_files();
                    scheduler.get_calldata(args.generate_smart_contract);
                }
                info!(target: "app","Caching of srs and pk files has ended: {:?}",path);
            }
        })
        .await
        .expect("cache srs pk should success");

        info!(target: "app","Caching of srs and pk files has ended");
    }

    let (tx, mut rx) = integration.mpsc;

    let challenge_storage_clone = integration.storage.clone();
    let receive_tasks = task::spawn(async move {
        init_server(tx, challenge_storage_clone).await.expect("init server error");
    });

    let execute_tasks = task::spawn(async move {
        while let original_proof = rx.recv().await {
            let scheduler_running = integration.scheduler.clone();
            let challenge_storage = integration.storage.clone();
            let challenge = Arc::new(Mutex::new(Challenge::default()));
            let challenge_scheduler = challenge.clone();
            let scheduler_result = task::spawn_blocking(move || {
                let challenge_id = original_proof.clone().unwrap().task_id;
                {
                    challenge_scheduler.lock().update_challenge_id(challenge_id);
                }
                info!(target: "app","Start generating proof for Challenge: {:?}",challenge_id);

                // clear
                let mut clear = Command::new("sh")
                    .arg("./scripts/clear_snark.sh")
                    .spawn()
                    .expect("Failed to execute command");
                let _ = clear.wait();
                let constructor = original_proof.clone().unwrap().get_constructor_by_parse_proof();
                {
                    let mut scheduler = scheduler_running.lock();
                    scheduler.update(constructor, 1);
                    scheduler.get_calldata(args.generate_smart_contract)
                }
            })
            .await;

            match scheduler_result {
                Ok(proof) => {
                    challenge.lock().update_proof(proof);
                    info!(target: "app","Successfully generated proof for Challenge: {:?}",challenge.lock().challenge_id);

                    println!("prove success")
                }
                Err(err) => {
                    warn!(target: "app","Failed to generate proof for Challenge: {:?},err: {}",challenge.lock().challenge_id,err);
                    eprintln!("prove error: {}", err)
                }
            }

            {
                let storage = challenge_storage.lock();
                let challenge = challenge.lock();

                storage
                    .storage_challenge_proof(challenge.challenge_id, challenge.proof.clone())
                    .expect("save success");

                info!(target: "app","Storage Challenge Prove Success: {:?}",challenge.challenge_id);
            }
        }
    });

    tokio::join!(receive_tasks, execute_tasks);
}

struct Challenge {
    challenge_id: H256,
    proof: String,
}

impl Challenge {
    fn default() -> Self {
        Self { challenge_id: H256::zero(), proof: "".to_string() }
    }

    fn update_challenge_id(&mut self, challenge_id: H256) {
        self.challenge_id = challenge_id;
    }

    fn update_proof(&mut self, proof: String) {
        self.proof = proof;
    }
}
