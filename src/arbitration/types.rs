use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::arbitration::helper::FinalAssemblyTask;
use crate::server::OriginalProof;
use crate::storage::contract_storage::util::ObContractStorageConstructor;

use crate::arbitration::network_pairs::NetworkPairs;
use crate::get_network_from_chain_id;
use ethers_core::types::{Address, Bytes, H256};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchBlocksMerkleInput {
    #[serde(rename(deserialize = "blockHashBatch"))]
    pub block_hash_batch: Vec<H256>,
    #[serde(rename(deserialize = "blockBatchMerkleRoot"))]
    pub block_batch_merkle_root: H256,
    #[serde(rename(deserialize = "targetBlockIndex"))]
    pub target_block_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchBlocksInput {
    #[serde(rename(deserialize = "batchData"))]
    pub batch_blocks_merkle: Vec<BatchBlocksMerkleInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<Bytes>,
    pub root: Option<H256>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObContractStorageInput {
    #[serde(rename(deserialize = "mdcAddress"))]
    pub mdc_address: Address,
    #[serde(rename(deserialize = "manageAddress"))]
    pub manage_address: Address,
    #[serde(rename(deserialize = "mdcCurrentEnableTimeBlockNumber"))]
    pub mdc_current_enable_time_block_number: u64,
    #[serde(rename(deserialize = "mdcNextEnableTimeBlockNumber"))]
    pub mdc_next_enable_time_block_number: u64,
    #[serde(rename(deserialize = "mdcCurrentRuleProof"), skip)]
    pub mdc_current_rule: MerkleProof,
    #[serde(rename(deserialize = "managerCurrentEnableTimeBlockNumber"))]
    pub manager_current_enable_time_block_number: u64,
    #[serde(rename(deserialize = "managerNextEnableTimeBlockNumber"))]
    pub manager_next_enable_time_block_number: u64,
    /// see [`ObContractStorageConstructor`]
    #[serde(rename(deserialize = "contractsSlotsHash"))]
    pub contracts_slots_hash: [H256; 10],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInput {
    #[serde(rename(deserialize = "transactionHash"))]
    pub transaction_hash: H256,
    #[serde(rename(deserialize = "transactionProof"), skip)]
    pub transaction_proof: MerkleProof,
    #[serde(rename(deserialize = "transactionProofEnable"))]
    pub transaction_proof_enable: bool,
    #[serde(rename(deserialize = "receiptProof"), skip)]
    pub receipt_proof: MerkleProof,
    #[serde(rename(deserialize = "receiptProofEnable"))]
    pub receipt_proof_enable: bool,
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
    #[serde(rename(deserialize = "sourceNetwork"))]
    pub source_network: u64,
    #[serde(rename(deserialize = "destNetwork"))]
    pub dest_network: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofInput {
    #[serde(rename(deserialize = "transactionsInput"))]
    pub transactions_input: TransactionsInput,
    #[serde(rename(deserialize = "obContractStorageInput"))]
    pub ob_contract_storage_input: Option<ObContractStorageInput>,
    #[serde(rename(deserialize = "blockBatchData"))]
    pub batch_blocks_input: BatchBlocksInput,
    #[serde(rename(deserialize = "config"))]
    pub config: ProofConfig,
}

impl ProofInput {
    pub fn get_final_task(self, round: usize) -> FinalAssemblyTask {
        let is_source = self.config.is_source;
        let source_network = get_network_from_chain_id(self.config.source_network).unwrap();
        let dest_network = get_network_from_chain_id(self.config.dest_network).unwrap();
        let pairs = NetworkPairs::new_pairs(source_network, dest_network, is_source).unwrap();
        let ob_contract_storage_input = self.ob_contract_storage_input;
        let batch_blocks_input = self.batch_blocks_input;
        let original_transaction = self.transactions_input.original_transaction;
        let commit_transaction = self.transactions_input.commit_transaction;
        let constructor = pairs.parse_pairs_task(
            ob_contract_storage_input,
            batch_blocks_input,
            original_transaction,
            commit_transaction,
        );

        let final_assembly_type =
            if is_source { FinalAssemblyType::Source } else { FinalAssemblyType::Destination };

        FinalAssemblyTask::new(
            round,
            final_assembly_type,
            source_network,
            dest_network,
            constructor,
        )
    }
}
#[derive(Clone, Debug)]
pub struct SchedulerRouterConstructor {
    pub proof: ProofInput,
}

impl OriginalProof {
    pub fn get_constructor_by_parse_proof(self) -> SchedulerRouterConstructor {
        let value: Value = serde_json::from_str(self.proof.as_str()).unwrap();
        let mut proof_params = serde_json::from_str::<ProofInput>(self.proof.as_str()).unwrap();

        // If the challenge is from L2, commit tx needs to be loaded
        if proof_params.config.is_l2 {
            let commit_transaction =
                proof_params.transactions_input.commit_transaction.clone().unwrap();
            if commit_transaction.transaction_proof_enable {
                let mut transaction_merkle_proof_proof: Vec<Bytes> = vec![];
                let proofs = value["transactionsInput"]["commitTransaction"]["transactionProof"]
                    ["proof"]
                    .as_array()
                    .unwrap();
                for proof in proofs {
                    let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
                    transaction_merkle_proof_proof.push(Bytes::from(proof_bytes));
                }

                let transaction_merkle_proof = MerkleProof {
                    key: Vec::from_hex(
                        &value["transactionsInput"]["commitTransaction"]["transactionProof"]["key"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap(),
                    value: Vec::from_hex(
                        &value["transactionsInput"]["commitTransaction"]["transactionProof"]
                            ["value"]
                            .as_str()
                            .unwrap(),
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

            if commit_transaction.receipt_proof_enable {
                let mut receipt_merkle_proof_proof: Vec<Bytes> = vec![];
                let proofs = value["transactionsInput"]["commitTransaction"]["receiptProof"]
                    ["proof"]
                    .as_array()
                    .unwrap();
                for proof in proofs {
                    let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
                    receipt_merkle_proof_proof.push(Bytes::from(proof_bytes));
                }

                let receipt_merkle_proof = MerkleProof {
                    key: Vec::from_hex(
                        &value["transactionsInput"]["commitTransaction"]["receiptProof"]["key"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap(),
                    value: Vec::from_hex(
                        &value["transactionsInput"]["commitTransaction"]["receiptProof"]["value"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap(),
                    proof: receipt_merkle_proof_proof,
                    root: None,
                };

                proof_params
                    .transactions_input
                    .commit_transaction
                    .as_mut()
                    .unwrap()
                    .receipt_proof = receipt_merkle_proof;
            }
        }

        // Load original tx
        if proof_params.transactions_input.original_transaction.transaction_proof_enable {
            let mut transaction_merkle_proof_proof: Vec<Bytes> = vec![];
            let proofs = value["transactionsInput"]["originalTransaction"]["transactionProof"]
                ["proof"]
                .as_array()
                .unwrap();
            for proof in proofs {
                let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
                transaction_merkle_proof_proof.push(Bytes::from(proof_bytes));
            }

            let transaction_merkle_proof = MerkleProof {
                key: Vec::from_hex(
                    &value["transactionsInput"]["originalTransaction"]["transactionProof"]["key"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                value: Vec::from_hex(
                    &value["transactionsInput"]["originalTransaction"]["transactionProof"]["value"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                proof: transaction_merkle_proof_proof,
                root: None,
            };

            proof_params.transactions_input.original_transaction.transaction_proof =
                transaction_merkle_proof;
        }
        if proof_params.transactions_input.original_transaction.receipt_proof_enable {
            let mut receipt_merkle_proof_proof: Vec<Bytes> = vec![];
            let proofs = value["transactionsInput"]["originalTransaction"]["receiptProof"]["proof"]
                .as_array()
                .unwrap();
            for proof in proofs {
                let proof_bytes = Vec::from_hex(proof.as_str().unwrap()).unwrap();
                receipt_merkle_proof_proof.push(Bytes::from(proof_bytes));
            }

            let receipt_merkle_proof = MerkleProof {
                key: Vec::from_hex(
                    &value["transactionsInput"]["originalTransaction"]["receiptProof"]["key"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                value: Vec::from_hex(
                    &value["transactionsInput"]["originalTransaction"]["receiptProof"]["value"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
                proof: receipt_merkle_proof_proof,
                root: None,
            };

            proof_params.transactions_input.original_transaction.receipt_proof =
                receipt_merkle_proof;
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

        SchedulerRouterConstructor { proof: proof_params }
    }
}
