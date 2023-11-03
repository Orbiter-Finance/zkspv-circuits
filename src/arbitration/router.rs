use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::arbitration::helper::ArbitrationTask::Final;
use crate::arbitration::helper::{
    ETHBlockTrackTask, FinalAssemblyConstructor, FinalAssemblyTask, MDCStateTask, TransactionTask,
};
use crate::arbitration::types::{EthereumSourceProof, ProofsRouter};
use crate::storage::util::{get_mdc_storage_circuit, EbcRuleParams, StorageConstructor};
use crate::track_block::util::{get_eth_track_block_circuit, TrackBlockConstructor};
use crate::transaction::ethereum::util::{get_eth_transaction_circuit, TransactionConstructor};
use crate::transaction::EthTransactionType;
use crate::util::scheduler::arbitration_scheduler::ArbitrationScheduler;
use crate::util::scheduler::Scheduler;
use crate::Network::{Arbitrum, Ethereum, Optimism, ZkSync};
use crate::{EthereumNetwork, Network};
use ark_std::{end_timer, start_timer};
use ethers_core::types::H256;
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
    pub fn new(proof: ProofsRouter, round: usize) -> Self {
        match &proof.network {
            Ethereum(_) => {
                let network = proof.network.clone();
                let scheduler = ArbitrationScheduler::new(
                    network,
                    false,
                    false,
                    PathBuf::from("configs/arbitration/"),
                    PathBuf::from("data/arbitration/"),
                    PathBuf::from("cache_data/arbitration/"),
                );
                if proof.source {
                    let proof = proof.ethereum_source_proof.unwrap().clone();

                    let ethereum_transaction_constructor = TransactionConstructor {
                        block_number: proof.transaction_proof.block_number as u32,
                        transaction_index: Option::from(proof.transaction_index as u32),
                        transaction_index_bytes: Option::from(
                            proof.transaction_proof.merkle_proof.key.clone(),
                        ),
                        transaction_rlp: proof.transaction_proof.merkle_proof.value.clone(),
                        merkle_proof: proof.transaction_proof.merkle_proof.proof.clone(),
                        transaction_pf_max_depth: proof
                            .transaction_proof
                            .merkle_proof
                            .proof
                            .clone()
                            .len(),
                        network,
                    };

                    let transaction_task = TransactionTask {
                        input: get_eth_transaction_circuit(
                            ethereum_transaction_constructor.clone(),
                        ),
                        tx_type: EthTransactionType::DynamicFeeTxType,
                        tasks_len: 1,
                        constructor: vec![ethereum_transaction_constructor],
                        aggregated: false,
                    };

                    let mdc_storage_constructor_pre = StorageConstructor {
                        block_number: proof.mdc_rule_proofs.mdc_pre_rule.block_number as u32,
                        address: proof.mdc_address,
                        slots: proof.mdc_rule_proofs.mdc_slots_hash.clone().to_vec(),
                        acct_pf_max_depth: 9,
                        storage_pf_max_depth: 8,
                        ebc_rule_params: EbcRuleParams {
                            ebc_rule_key: H256::from_slice(
                                &*proof.mdc_rule_proofs.mdc_pre_rule.merkle_proof.key.clone(),
                            ),
                            ebc_rule_root: proof
                                .mdc_rule_proofs
                                .mdc_pre_rule
                                .merkle_proof
                                .root
                                .unwrap(),
                            ebc_rule_value: proof
                                .mdc_rule_proofs
                                .mdc_pre_rule
                                .merkle_proof
                                .value
                                .clone(),
                            ebc_rule_merkle_proof: proof
                                .mdc_rule_proofs
                                .mdc_pre_rule
                                .merkle_proof
                                .proof
                                .clone(),
                            ebc_rule_pf_max_depth: proof
                                .mdc_rule_proofs
                                .mdc_pre_rule
                                .merkle_proof
                                .proof
                                .clone()
                                .len(),
                        },
                        network,
                    };

                    let mdc_storage_constructor_current = StorageConstructor {
                        block_number: proof.mdc_rule_proofs.mdc_current_rule.block_number as u32,
                        address: proof.mdc_address,
                        slots: proof.mdc_rule_proofs.mdc_slots_hash.clone().to_vec(),
                        acct_pf_max_depth: 9,
                        storage_pf_max_depth: 8,
                        ebc_rule_params: EbcRuleParams {
                            ebc_rule_key: H256::from_slice(
                                &*proof.mdc_rule_proofs.mdc_current_rule.merkle_proof.key.clone(),
                            ),
                            ebc_rule_root: proof
                                .mdc_rule_proofs
                                .mdc_current_rule
                                .merkle_proof
                                .root
                                .unwrap(),
                            ebc_rule_value: proof
                                .mdc_rule_proofs
                                .mdc_current_rule
                                .merkle_proof
                                .value
                                .clone(),
                            ebc_rule_merkle_proof: proof
                                .mdc_rule_proofs
                                .mdc_current_rule
                                .merkle_proof
                                .proof
                                .clone(),
                            ebc_rule_pf_max_depth: proof
                                .mdc_rule_proofs
                                .mdc_current_rule
                                .merkle_proof
                                .proof
                                .clone()
                                .len(),
                        },
                        network,
                    };

                    let mdc_storage_pre_task = MDCStateTask {
                        input: get_mdc_storage_circuit(mdc_storage_constructor_pre.clone()),
                        tasks_len: 1,
                        task_width: 1,
                        constructor: vec![mdc_storage_constructor_pre],
                    };
                    let mdc_storage_current_task = MDCStateTask {
                        input: get_mdc_storage_circuit(mdc_storage_constructor_current.clone()),
                        tasks_len: 1,
                        task_width: 1,
                        constructor: vec![mdc_storage_constructor_current],
                    };

                    let block_track_constructor = TrackBlockConstructor {
                        blocks_number: vec![
                            proof.transaction_proof.block_number,
                            proof.mdc_rule_proofs.mdc_pre_rule.block_number,
                            proof.mdc_rule_proofs.mdc_current_rule.block_number,
                        ],
                        network,
                    };

                    let block_track_task = ETHBlockTrackTask {
                        input: get_eth_track_block_circuit(block_track_constructor.clone()),
                        network,
                        tasks_len: 1,
                        task_width: 3,
                        constructor: vec![block_track_constructor],
                    };

                    let constructor = FinalAssemblyConstructor {
                        transaction_task: Option::from(transaction_task),
                        eth_block_track_task: Option::from(block_track_task),
                        mdc_state_task: Option::from(vec![
                            mdc_storage_pre_task,
                            mdc_storage_current_task,
                        ]),
                    };

                    let task = FinalAssemblyTask {
                        round,
                        aggregation_type: FinalAssemblyType::Source,
                        network,
                        constructor,
                    };

                    ProofRouter { arbitration_scheduler: scheduler, task }
                } else {
                    let proof = proof.ethereum_dest_proof.unwrap().clone();

                    let ethereum_transaction_constructor = TransactionConstructor {
                        block_number: proof.transaction_proof.block_number as u32,
                        transaction_index: Option::from(proof.transaction_index as u32),
                        transaction_index_bytes: Option::from(
                            proof.transaction_proof.merkle_proof.key.clone(),
                        ),
                        transaction_rlp: proof.transaction_proof.merkle_proof.value.clone(),
                        merkle_proof: proof.transaction_proof.merkle_proof.proof.clone(),
                        transaction_pf_max_depth: proof
                            .transaction_proof
                            .merkle_proof
                            .proof
                            .clone()
                            .len(),
                        network,
                    };

                    let transaction_task = TransactionTask {
                        input: get_eth_transaction_circuit(
                            ethereum_transaction_constructor.clone(),
                        ),
                        tx_type: EthTransactionType::DynamicFeeTxType,
                        tasks_len: 1,
                        constructor: vec![ethereum_transaction_constructor],
                        aggregated: false,
                    };

                    let block_track_constructor = TrackBlockConstructor {
                        blocks_number: vec![proof.transaction_proof.block_number],
                        network,
                    };

                    let block_track_task = ETHBlockTrackTask {
                        input: get_eth_track_block_circuit(block_track_constructor.clone()),
                        network,
                        tasks_len: 1,
                        task_width: 1,
                        constructor: vec![block_track_constructor],
                    };

                    let constructor = FinalAssemblyConstructor {
                        transaction_task: Option::from(transaction_task),
                        eth_block_track_task: Option::from(block_track_task),
                        mdc_state_task: None,
                    };

                    let task = FinalAssemblyTask {
                        round,
                        aggregation_type: FinalAssemblyType::Destination,
                        network,
                        constructor,
                    };
                    ProofRouter { arbitration_scheduler: scheduler, task }
                }
            }
            Arbitrum(_) => {
                todo!()
            }
            Optimism(_) => {
                todo!()
            }
            ZkSync(_) => {
                todo!()
            }
        }
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
