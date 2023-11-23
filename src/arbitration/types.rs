use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::arbitration::helper::{
    BlockMerkleInclusionTask, ETHBlockTrackTask, EthTransactionTask, FinalAssemblyConstructor,
    FinalAssemblyTask, MDCStateTask, ZkSyncTransactionTask,
};
use crate::server::OriginalProof;
use crate::storage::contract_storage::util::{
    get_contracts_storage_circuit, EbcRuleParams, MultiBlocksContractsStorageConstructor,
    ObContractStorageConstructor, SingleBlockContractsStorageConstructor,
};
use crate::track_block::util::{
    get_eth_track_block_circuit, get_merkle_inclusion_circuit, TrackBlockConstructor,
};
use crate::track_block::{BlockMerkleInclusionCircuit, BlockMerkleInclusionConstructor};
use crate::transaction::util::{
    get_eth_transaction_circuit, get_zksync_transaction_circuit, TransactionConstructor,
};
use crate::transaction::EthTransactionType;
use crate::{get_network_from_chain_id, Network};
use ark_std::Zero;
use ethers_core::types::{Address, Bytes, H256};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockData {
    #[serde(rename(deserialize = "blockHashBatch"))]
    pub block_hash_batch: Vec<H256>,
    #[serde(rename(deserialize = "blockBatchMerkleRoot"))]
    pub block_batch_merkle_root: H256,
    #[serde(rename(deserialize = "targetBlockIndex"))]
    pub target_block_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchData {
    #[serde(rename(deserialize = "batchData"))]
    pub batch_data: Vec<BlockData>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<Bytes>,
    pub root: Option<H256>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchBlocksMerkleInput {
    #[serde(rename(deserialize = "startBlockNumber"))]
    pub start_block_number: u64,
    #[serde(rename(deserialize = "endBlockNumber"))]
    pub end_block_number: u64,
    #[serde(rename(deserialize = "targetBlockNumber"))]
    pub target_block_number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObContractStorageInput {
    #[serde(rename(deserialize = "mdcAddress"))]
    pub mdc_address: Address,
    #[serde(rename(deserialize = "manageAddress"))]
    pub manage_address: Address,
    #[serde(rename(deserialize = "mdcCurrentBatchBlocksMerkle"))]
    pub mdc_current_batch_blocks_merkle: BatchBlocksMerkleInput,
    #[serde(rename(deserialize = "mdcNextBatchBlocksMerkle"))]
    pub mdc_next_batch_blocks_merkle: BatchBlocksMerkleInput,
    #[serde(rename(deserialize = "mdcCurrentRuleProof"), skip)]
    pub mdc_current_rule: MerkleProof,
    /// see [`ObContractStorageConstructor`]
    #[serde(rename(deserialize = "contractsSlotsHash"))]
    pub contracts_slots_hash: [H256; 9],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInput {
    #[serde(rename(deserialize = "transactionHash"))]
    pub transaction_hash: H256,
    #[serde(rename(deserialize = "transactionBatchBlocksMerkle"))]
    pub batch_blocks_merkle: BatchBlocksMerkleInput,
    #[serde(rename(deserialize = "transactionProof"), skip)]
    pub transaction_proof: MerkleProof,
    #[serde(rename(deserialize = "transactionProofEnable"))]
    pub transaction_proof_enable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionsInput {
    #[serde(rename(deserialize = "originalTransaction"))]
    pub original_transaction: TransactionInput,
    #[serde(rename(deserialize = "commitTransaction"))]
    pub commit_transaction: Option<TransactionInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofConfig {
    #[serde(rename(deserialize = "isSource"))]
    pub is_source: bool,
    #[serde(rename(deserialize = "isL2"))]
    pub is_l2: bool,
    #[serde(rename(deserialize = "l1Network"))]
    pub l1_network: u64,
    #[serde(rename(deserialize = "l2Network"))]
    pub l2_network: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofInput {
    #[serde(rename(deserialize = "transactionsInput"))]
    pub transactions_input: TransactionsInput,
    #[serde(rename(deserialize = "obContractStorageInput"))]
    pub ob_contract_storage_input: Option<ObContractStorageInput>,
    #[serde(rename(deserialize = "blockBatchData"))]
    pub block_batch_data: Option<BatchData>,
    #[serde(rename(deserialize = "config"))]
    pub config: ProofConfig,
}

impl ProofInput {
    pub fn get_final_assembly_task(self, round: usize) -> FinalAssemblyTask {
        let is_source = self.config.is_source;
        let is_l2 = self.config.is_l2;
        let l1_network = get_network_from_chain_id(self.config.l1_network).unwrap();
        let l2_network = if is_l2 {
            Some(get_network_from_chain_id(self.config.l2_network).unwrap())
        } else {
            None
        };

        let eth_transaction_task;
        let zksync_transaction_task;
        let block_merkle_inclusion_task;
        // let eth_block_track_task;
        let mdc_state_task;

        {
            let ob_contract_storage_input = self.ob_contract_storage_input;
            // get mdc_state_task
            // This part completes the proof on the L1 network
            if is_source {
                let ob_contract_storage_input = ob_contract_storage_input.as_ref().unwrap();
                {
                    let mdc_contract_storage_current_constructor = ObContractStorageConstructor {
                        contract_address: ob_contract_storage_input.mdc_address,
                        slots: ob_contract_storage_input.contracts_slots_hash[..5].to_vec(),
                        acct_pf_max_depth: 9,
                        storage_pf_max_depth: 8,
                    };

                    let manage_contract_storage_current_constructor =
                        ObContractStorageConstructor {
                            contract_address: ob_contract_storage_input.manage_address,
                            slots: ob_contract_storage_input.contracts_slots_hash[5..].to_vec(),
                            acct_pf_max_depth: 9,
                            storage_pf_max_depth: 8,
                        };

                    let mdc_contract_storage_next_constructor = ObContractStorageConstructor {
                        contract_address: ob_contract_storage_input.mdc_address,
                        slots: ob_contract_storage_input.contracts_slots_hash[1..3].to_vec(),
                        acct_pf_max_depth: 9,
                        storage_pf_max_depth: 8,
                    };

                    let single_block_contracts_storage_constructor_current =
                        SingleBlockContractsStorageConstructor {
                            block_number: ob_contract_storage_input
                                .mdc_current_batch_blocks_merkle
                                .target_block_number
                                as u32,
                            block_contracts_storage: vec![
                                mdc_contract_storage_current_constructor,
                                manage_contract_storage_current_constructor,
                            ],
                        };
                    let single_block_contracts_storage_constructor_next =
                        SingleBlockContractsStorageConstructor {
                            block_number: ob_contract_storage_input
                                .mdc_next_batch_blocks_merkle
                                .target_block_number
                                as u32,
                            block_contracts_storage: vec![mdc_contract_storage_next_constructor],
                        };

                    let ob_contracts_constructor = MultiBlocksContractsStorageConstructor {
                        blocks_contracts_storage: vec![
                            single_block_contracts_storage_constructor_current,
                            single_block_contracts_storage_constructor_next,
                        ],
                        ebc_rule_params: EbcRuleParams {
                            ebc_rule_key: H256::from_slice(
                                &*ob_contract_storage_input.mdc_current_rule.key.clone(),
                            ),
                            ebc_rule_root: ob_contract_storage_input.mdc_current_rule.root.unwrap(),
                            ebc_rule_value: ob_contract_storage_input
                                .mdc_current_rule
                                .value
                                .clone(),
                            ebc_rule_merkle_proof: ob_contract_storage_input
                                .mdc_current_rule
                                .proof
                                .clone(),
                            ebc_rule_pf_max_depth: 8,
                        },
                        network: l1_network,
                    };

                    mdc_state_task = Some(MDCStateTask {
                        input: get_contracts_storage_circuit(ob_contracts_constructor.clone()),
                        single_block_include_contracts: 2,
                        multi_blocks_number: 2,
                        constructor: vec![ob_contracts_constructor],
                        aggregated: false,
                    });
                }
                println!("With mdc_state_task for L1");
            } else {
                mdc_state_task = None;
                println!("No mdc_state_task for L1")
            }

            // get block_merkle_inclusion_task
            // This part completes the proof on the L1 network
            {
                block_merkle_inclusion_task = if self.block_batch_data.is_some() {
                    let input = BlockMerkleInclusionCircuit::from_json_object(
                        self.block_batch_data.unwrap(),
                    );
                    Some(BlockMerkleInclusionTask {
                        input: input.clone(),
                        network: l1_network,
                        tree_depth: 8,
                        block_batch_num: input.block_batch_num,
                        block_range_length: input.block_range_length,
                    })
                } else {
                    println!("No block_merkle_inclusion_task");
                    None
                };
            }

            // get eth_transaction_task or zksync_transaction_task
            // is_l2 == false,This part completes the proof on the L1 network;is_l2 == true,This part completes the proof on the L2 network;
            {
                let network = if is_l2 { l2_network.unwrap() } else { l1_network };
                let original_transaction = self.transactions_input.original_transaction.clone();
                let original_transaction_constructor = TransactionConstructor::new(
                    original_transaction.transaction_hash,
                    Some(original_transaction.transaction_proof.key.clone()),
                    Some(original_transaction.transaction_proof.value.clone()),
                    Some(original_transaction.transaction_proof.proof.clone()),
                    Some(original_transaction.transaction_proof.proof.clone().len()),
                    network,
                );

                if is_l2 && matches!(network, Network::ZkSync(_)) {
                    let commit_transaction =
                        self.transactions_input.commit_transaction.unwrap().clone();
                    let commit_transaction_constructor = TransactionConstructor::new(
                        commit_transaction.transaction_hash,
                        Some(commit_transaction.transaction_proof.key.clone()),
                        Some(commit_transaction.transaction_proof.value.clone()),
                        Some(commit_transaction.transaction_proof.proof.clone()),
                        Some(commit_transaction.transaction_proof.proof.clone().len()),
                        network,
                    );
                    zksync_transaction_task = Some(ZkSyncTransactionTask {
                        input: get_zksync_transaction_circuit(
                            original_transaction_constructor.clone(),
                        ),
                        tx_type: EthTransactionType::DynamicFeeTxType,
                        tasks_len: 1,
                        constructor: vec![original_transaction_constructor],
                        aggregated: false,
                        network,
                    });
                    eth_transaction_task = Some(EthTransactionTask {
                        input: get_eth_transaction_circuit(commit_transaction_constructor.clone()),
                        tx_type: EthTransactionType::DynamicFeeTxType,
                        tasks_len: 1,
                        constructor: vec![commit_transaction_constructor],
                        aggregated: false,
                        network,
                    });
                } else {
                    eth_transaction_task = Some(EthTransactionTask {
                        input: get_eth_transaction_circuit(
                            original_transaction_constructor.clone(),
                        ),
                        tx_type: EthTransactionType::DynamicFeeTxType,
                        tasks_len: 1,
                        constructor: vec![original_transaction_constructor],
                        aggregated: false,
                        network,
                    });
                    zksync_transaction_task = None;
                }

                println!("With transaction_task for {} Network", network.to_string());
            }
        }

        let constructor = FinalAssemblyConstructor {
            eth_transaction_task,
            zksync_transaction_task,
            mdc_state_task,
            eth_block_track_task: None,
            block_merkle_inclusion_task,
        };

        let final_assembly_type =
            if is_source { FinalAssemblyType::Source } else { FinalAssemblyType::Destination };

        FinalAssemblyTask::new(round, final_assembly_type, l1_network, l2_network, constructor)
    }
}
#[derive(Clone, Debug)]
pub struct ProofRouterConstructor {
    pub proof: ProofInput,
}

impl OriginalProof {
    pub fn get_constructor_by_parse_proof(self) -> ProofRouterConstructor {
        let value: Value = serde_json::from_str(self.proof.as_str()).unwrap();
        let mut proof_params = serde_json::from_str::<ProofInput>(self.proof.as_str()).unwrap();

        // Load original or commit transaction merkle proof
        if proof_params.config.is_l2 {
            let commit_transaction =
                proof_params.transactions_input.commit_transaction.clone().unwrap();
            if commit_transaction.transaction_proof_enable {
                let mut transaction_merkle_proof_proof: Vec<Bytes> = vec![];
                let proofs =
                    value["transactionInput"]["transactionProof"]["proof"].as_array().unwrap();
                for proof in proofs {
                    let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
                    transaction_merkle_proof_proof.push(Bytes::from(proof_bytes));
                }

                let transaction_merkle_proof = MerkleProof {
                    key: Vec::from_hex(
                        &value["transactionInput"]["transactionProof"]["key"].as_str().unwrap(),
                    )
                    .unwrap(),
                    value: Vec::from_hex(
                        &value["transactionInput"]["transactionProof"]["value"].as_str().unwrap(),
                    )
                    .unwrap(),
                    proof: transaction_merkle_proof_proof,
                    root: None,
                };

                proof_params
                    .transactions_input
                    .commit_transaction
                    .as_mut()
                    .unwrap()
                    .transaction_proof = transaction_merkle_proof;
            }
        }
        if proof_params.transactions_input.original_transaction.transaction_proof_enable {
            let mut transaction_merkle_proof_proof: Vec<Bytes> = vec![];
            let proofs = value["transactionInput"]["transactionProof"]["proof"].as_array().unwrap();
            for proof in proofs {
                let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
                transaction_merkle_proof_proof.push(Bytes::from(proof_bytes));
            }

            let transaction_merkle_proof = MerkleProof {
                key: Vec::from_hex(
                    &value["transactionInput"]["transactionProof"]["key"].as_str().unwrap(),
                )
                .unwrap(),
                value: Vec::from_hex(
                    &value["transactionInput"]["transactionProof"]["value"].as_str().unwrap(),
                )
                .unwrap(),
                proof: transaction_merkle_proof_proof,
                root: None,
            };

            proof_params.transactions_input.original_transaction.transaction_proof =
                transaction_merkle_proof;
        }

        // Load mdc current rule merkle proof
        if proof_params.config.is_source {
            let mut mdc_current_rule_merkle_proof_proof: Vec<Bytes> = vec![];
            let proofs =
                value["obContractStorageInput"]["mdcCurrentRuleProof"]["proof"].as_array().unwrap();
            for proof in proofs {
                let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
                mdc_current_rule_merkle_proof_proof.push(Bytes::from(proof_bytes));
            }

            let mdc_pre_rule_merkle_proof = MerkleProof {
                key: Vec::from_hex(
                    &value["obContractStorageInput"]["mdcCurrentRuleProof"]["key"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                value: Vec::from_hex(
                    &value["obContractStorageInput"]["mdcCurrentRuleProof"]["value"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                proof: mdc_current_rule_merkle_proof_proof,
                root: Option::from(
                    H256::from_str(
                        &value["obContractStorageInput"]["mdcCurrentRuleProof"]["root"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap(),
                ),
            };

            proof_params.ob_contract_storage_input.as_mut().unwrap().mdc_current_rule =
                mdc_pre_rule_merkle_proof;
        }

        ProofRouterConstructor { proof: proof_params }
    }
}
