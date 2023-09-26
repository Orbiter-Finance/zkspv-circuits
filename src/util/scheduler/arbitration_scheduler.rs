use crate::{
    arbitration::helper::ArbitrationTask,
    storage::{util::get_mdc_storage_circuit, EthBlockStorageCircuit},
    track_block::{util::get_eth_track_block_circuit, EthTrackBlockCircuit},
    util::circuit::PublicAggregationCircuit,
    Network,
};

use super::EthScheduler;
use crate::storage::util::StorageConstructor;
use crate::track_block::util::TrackBlockConstructor;
use crate::transaction::ethereum::EthBlockTransactionCircuit;
use crate::util::scheduler::{self, AnyCircuit};
use circuit_derive::AnyCircuit;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::Snark;
use std::path::Path;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, AnyCircuit)]
pub enum CircuitRouter {
    Transaction(EthBlockTransactionCircuit),
    AggreateTransactions(PublicAggregationCircuit),

    BlockTrackInterval(EthTrackBlockCircuit),
    AggreateBlockTracks(PublicAggregationCircuit),

    MdcStorage(EthBlockStorageCircuit),
    AggreateMdcStorages(PublicAggregationCircuit),
}

pub type ArbitrationScheduler = EthScheduler<ArbitrationTask>;

impl scheduler::Scheduler for ArbitrationScheduler {
    type Task = ArbitrationTask;

    type CircuitRouter = CircuitRouter;

    fn get_circuit(&self, task: Self::Task, prev_snarks: Vec<Snark>) -> Self::CircuitRouter {
        match task {
            ArbitrationTask::Transaction(task) => {
                if task.tasks_len == 1 {
                    println!("TASK_LEN1======");
                    CircuitRouter::Transaction(task.input)
                } else {
                    println!("AGGREGATION ====== prev_snarks len {}", prev_snarks.len());
                    return CircuitRouter::AggreateTransactions(PublicAggregationCircuit::new(
                        prev_snarks
                            .into_iter()
                            .map(|snark| {
                                println!("instances num {}", snark.instances.len());
                                (snark, false)
                            })
                            .collect(),
                    ));
                }
            }
            ArbitrationTask::MDCState(task) => {
                if task.tasks_len == 1 {
                    println!("TASK_LEN1======");
                    CircuitRouter::MdcStorage(task.input)
                } else {
                    println!("AGGREGATION ====== prev_snarks len {}", prev_snarks.len());
                    return CircuitRouter::AggreateMdcStorages(PublicAggregationCircuit::new(
                        prev_snarks
                            .into_iter()
                            .map(|snark| {
                                println!("instances num {}", snark.instances.len());
                                (snark, false)
                            })
                            .collect(),
                    ));
                }
            }
            ArbitrationTask::ETHBlockTrack(task) => {
                if task.tasks_len == 1 {
                    println!("TASK_LEN1======");
                    CircuitRouter::BlockTrackInterval(task.input)
                } else {
                    println!("AGGREGATION ====== prev_snarks len {}", prev_snarks.len());
                    return CircuitRouter::AggreateBlockTracks(PublicAggregationCircuit::new(
                        prev_snarks
                            .into_iter()
                            .map(|snark| {
                                println!("instances num {}", snark.instances.len());
                                (snark, false)
                            })
                            .collect(),
                    ));
                }
            }
            ArbitrationTask::Final(_) => todo!(),
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
