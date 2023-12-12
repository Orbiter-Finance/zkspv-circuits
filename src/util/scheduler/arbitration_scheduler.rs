use crate::{
    arbitration::helper::ArbitrationTask,
    storage::{util::get_mdc_storage_circuit, EthBlockStorageCircuit},
    track_block::{
        util::get_eth_track_block_circuit, BlockMerkleInclusionCircuit, EthTrackBlockCircuit,
    },
    util::circuit::PublicAggregationCircuit,
    Network,
};

use super::EthScheduler;
use crate::arbitration::circuit_types::FinalAssemblyFinality;
use crate::receipt::EthBlockReceiptCircuit;
use crate::storage::contract_storage::ObContractsStorageCircuit;
use crate::storage::util::StorageConstructor;
use crate::track_block::util::TrackBlockConstructor;
use crate::transaction::ethereum::EthBlockTransactionCircuit;
use crate::transaction::zksync_era::ZkSyncEraBlockTransactionCircuit;
use crate::transaction_receipt::TransactionReceiptCircuit;
use crate::util::scheduler::{self, AnyCircuit, Task};
use circuit_derive::AnyCircuit;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use itertools::Itertools;
use snark_verifier_sdk::Snark;
use std::path::{Path, PathBuf};

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, AnyCircuit)]
pub enum CircuitRouter {
    EthTransaction(EthBlockTransactionCircuit),
    AggreateEthTransactions(PublicAggregationCircuit),

    ZkSyncTransaction(ZkSyncEraBlockTransactionCircuit),
    AggreateZkSyncTransactions(PublicAggregationCircuit),

    EthReceipt(EthBlockReceiptCircuit),
    AggreateEthReceipt(PublicAggregationCircuit),

    EthTransactionReceipt(TransactionReceiptCircuit),
    AggreateEthTransactionReceipt(PublicAggregationCircuit),

    BlockerMerkleInclusion(BlockMerkleInclusionCircuit),

    MdcStorage(ObContractsStorageCircuit),
    AggreateMdcStorages(PublicAggregationCircuit),

    // FinalAssembly(FinalAssemblyCircuit),
    Passthrough(PublicAggregationCircuit),
    FinalAssemblyThroughAggregation(PublicAggregationCircuit),
}

pub type ArbitrationScheduler = EthScheduler<ArbitrationTask>;

impl ArbitrationScheduler {
    pub fn default(network: Network) -> Self {
        ArbitrationScheduler::new(
            network,
            false,
            false,
            PathBuf::from("configs/arbitration/"),
            PathBuf::from("data/arbitration/"),
            PathBuf::from("cache_data/arbitration/"),
        )
    }
}

impl scheduler::Scheduler for ArbitrationScheduler {
    type Task = ArbitrationTask;

    type CircuitRouter = CircuitRouter;

    fn get_circuit(&self, task: Self::Task, prev_snarks: Vec<Snark>) -> Self::CircuitRouter {
        match task {
            ArbitrationTask::EthTransaction(task) => {
                if task.circuit_type().is_aggregated() {
                    println!(
                        "EthTransaction AGGREGATION ====== prev_snarks len {}",
                        prev_snarks.len()
                    );
                    let prev_snarks = prev_snarks
                        .into_iter()
                        .map(|snark| {
                            println!("instances num {}", snark.instances.len());
                            (snark, false)
                        })
                        .collect_vec();
                    CircuitRouter::AggreateEthTransactions(PublicAggregationCircuit::new(
                        prev_snarks,
                    ))
                } else {
                    println!("TASK_LEN1======");
                    CircuitRouter::EthTransaction(task.input)
                }
            }
            ArbitrationTask::ZkSyncTransaction(task) => {
                if task.circuit_type().is_aggregated() {
                    println!(
                        "ZkSyncTransaction AGGREGATION ====== prev_snarks len {}",
                        prev_snarks.len()
                    );
                    let prev_snarks = prev_snarks
                        .into_iter()
                        .map(|snark| {
                            println!("instances num {}", snark.instances.len());
                            (snark, false)
                        })
                        .collect_vec();
                    CircuitRouter::AggreateZkSyncTransactions(PublicAggregationCircuit::new(
                        prev_snarks,
                    ))
                } else {
                    println!("TASK_LEN1======");
                    CircuitRouter::ZkSyncTransaction(task.input)
                }
            }
            ArbitrationTask::EthReceipt(task) => {
                if task.circuit_type().is_aggregated() {
                    println!("EthReceipt AGGREGATION ====== prev_snarks len {}", prev_snarks.len());
                    let prev_snarks = prev_snarks
                        .into_iter()
                        .map(|snark| {
                            println!("EthReceipt instances num {}", snark.instances.len());
                            (snark, false)
                        })
                        .collect_vec();
                    CircuitRouter::AggreateEthReceipt(PublicAggregationCircuit::new(prev_snarks))
                } else {
                    println!("TASK_LEN1======");
                    CircuitRouter::EthReceipt(task.input)
                }
            }
            ArbitrationTask::EthTransactionReceipt(task) => {
                if task.circuit_type().is_aggregated() {
                    println!(
                        "EthTransactionReceipt AGGREGATION ====== prev_snarks len {}",
                        prev_snarks.len()
                    );
                    let prev_snarks = prev_snarks
                        .into_iter()
                        .map(|snark| {
                            println!(
                                "EthTransactionReceipt instances num {}",
                                snark.instances.len()
                            );
                            (snark, false)
                        })
                        .collect_vec();
                    CircuitRouter::AggreateEthTransactionReceipt(PublicAggregationCircuit::new(
                        prev_snarks,
                    ))
                } else {
                    println!("TASK_LEN1======");
                    CircuitRouter::EthTransactionReceipt(task.input)
                }
            }
            ArbitrationTask::MDCState(task) => {
                if task.circuit_type().is_aggregated() {
                    println!(
                        "OB Contracts Storage AGGREGATION ====== prev_snarks len {}",
                        prev_snarks.len()
                    );
                    return CircuitRouter::AggreateMdcStorages(PublicAggregationCircuit::new(
                        prev_snarks
                            .into_iter()
                            .map(|snark| {
                                println!("instances num {}", snark.instances.len());
                                (snark, false)
                            })
                            .collect(),
                    ));
                } else {
                    println!("OB Contracts Storage TASK_LEN1======");
                    CircuitRouter::MdcStorage(task.input)
                }
            }
            ArbitrationTask::BlockMerkleInclusion(task) => {
                CircuitRouter::BlockerMerkleInclusion(task.input)
            }
            ArbitrationTask::Final(final_task) => {
                println!("FINAL ====== prev_snarks len {}", prev_snarks.len());
                if final_task.circuit_type().round != 0 {
                    assert_eq!(prev_snarks.len(), 1);
                    return CircuitRouter::Passthrough(PublicAggregationCircuit::new(
                        prev_snarks.into_iter().map(|snark| (snark, true)).collect(),
                    ));
                }

                let prev_snarks = prev_snarks
                    .into_iter()
                    .map(|snark| {
                        println!("instances num {}", snark.instances.len());
                        (snark, false)
                    })
                    .collect_vec();
                CircuitRouter::FinalAssemblyThroughAggregation(PublicAggregationCircuit::new(
                    prev_snarks,
                ))

                // FinalAssemblyCircuit
                // let [transaction_snark, block_snark]: [_; 2] = prev_snarks.try_into().unwrap();
                // CircuitRouter::FinalAssembly(FinalAssemblyCircuit::new(
                //     (transaction_snark, false),
                //     (block_snark, false), // (mdc_state_snark, false),
                // ))
            }
        }
    }
}

// a trait for arbitration, in our business, each network(Arb, OP, ZKS, Ethereum...) should have
// their own circuit and verifiy contract
pub trait ArbitrationBus {
    // Every Network would have own tx circuit
    fn get_cross_tx_circuit();

    // for MDC config on L1(Ethereum)
    fn get_storage_circuit(constructor: StorageConstructor) -> EthBlockStorageCircuit {
        get_mdc_storage_circuit(constructor)
    }

    // Track Block from L1(Ethereum)
    fn get_track_block_circuit(constructor: TrackBlockConstructor) -> EthTrackBlockCircuit {
        get_eth_track_block_circuit(constructor)
    }

    // need to proof three mdc config, tx_time as tx happened in cross chain network, block_n as the tx_time in L1 block number
    // then proof $block_{n-1}$, $block_{n}$, $block{n+1}$, so the correspond public input should contain
    // - time_{n-1}, block_{n-1}, mdc_{n-1}
    // - time_{n}, block_{n}, mdc_{n}
    // - time_{n+1}, block_{n+1}, mdc_{n}
    // mdc: {token_address, min_amt, max_amt, repay_time, exp_time}
    // so on Arbitration Verify Contract, should constraint
    //
    fn generate_mdc_continuity_proof(&self, network: Network, block_range: [u32; 3]) {}

    // for Arb, Op, ZKS, Ethereum... Cross Chain Tx validation
    // public input should contain
    // - tx_block_hash
    // - tx_network_id
    // - tx_timestamp
    // - token_address
    // - transfer_amt
    // - transfer_from
    // - transfer_to
    // - L1_tx_block_num
    fn genrate_tx_proof();

    // for L1(Ethereum) block track
    // public input should contain
    // - (pre_block_num, block_{n-1})
    // - (mid_block_num, block_{n})
    // - (pos_block_num, block_{n+1})
    // - {l2_anchor_l1_block_num, block_{k}}
    fn generate_track_block_proof();

    fn agg_final_proof();

    // Every network task would have own verify contract
    fn gen_verify_contract();

    fn gen_proving_key();
}

pub struct EthereumArbitration {}

impl EthereumArbitration {
    pub fn new() {}
}
