use tokio::sync::mpsc;
use tokio::task;
use zkspv_circuits::arbitration::router::ProofRouter;
use zkspv_circuits::server::client::{send_to_client, GENERATE_SUCCESS};
use zkspv_circuits::server::{init_server, OriginalProof};

#[tokio::main]
async fn main() {
    let (tx, mut rx) = mpsc::unbounded_channel::<OriginalProof>();
    let receive_tasks = task::spawn(async move {
        init_server(tx).await.expect("init server error");
    });

    let execute_tasks = task::spawn(async move {
        while let original_proof = rx.recv().await {
            task::spawn_blocking(|| {
                let constructor = original_proof.clone().unwrap().get_constructor_by_parse_proof();
                let task = ProofRouter::new(constructor, 1);
                let proof = task.get_calldata(true);
                //Todo: add error
                let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
                    send_to_client(original_proof.unwrap().task_id, proof, GENERATE_SUCCESS).await
                });

                match result {
                    Ok(_) => println!("send_to_client success"),
                    Err(err) => eprintln!("send_to_client error: {}", err),
                }
            })
            .await
            .unwrap();
        }
    });

    tokio::join!(receive_tasks, execute_tasks);
}
