use crate::storage::contract_storage::util::ObContractStorageConstructor;
use crate::Network;
use ethers_core::types::{Address, Bytes, H256};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<Bytes>,
    pub root: Option<H256>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleAndAnchorProof {
    #[serde(skip)]
    pub merkle_proof: MerkleProof,
    #[serde(rename(deserialize = "blockNumber"))]
    pub block_number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MdcRuleProofs {
    #[serde(rename(deserialize = "mdcPreRule"))]
    pub mdc_pre_rule: MerkleAndAnchorProof,
    #[serde(rename(deserialize = "mdcCurrentRule"))]
    pub mdc_current_rule: MerkleAndAnchorProof,
}

// Ethereum

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumSourceProof {
    #[serde(rename(deserialize = "mdcAddress"))]
    pub mdc_address: Address,
    #[serde(rename(deserialize = "manageAddress"))]
    pub manage_address: Address,
    #[serde(rename(deserialize = "transactionProof"))]
    pub transaction_proof: MerkleAndAnchorProof,
    #[serde(rename(deserialize = "transactionIndex"))]
    pub transaction_index: u64,
    #[serde(rename(deserialize = "mdcRuleProofs"))]
    pub mdc_rule_proofs: MdcRuleProofs,
    /// see [`ObContractStorageConstructor`]
    #[serde(rename(deserialize = "contractsSlotsHash"))]
    pub contracts_slots_hash: [H256; 9],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumDestProof {
    #[serde(rename(deserialize = "transactionProof"))]
    pub transaction_proof: MerkleAndAnchorProof,
    #[serde(rename(deserialize = "transactionIndex"))]
    pub transaction_index: u64,
}

// Arbitrum

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArbitrumSourceProof {
    #[serde(rename(deserialize = "mdcAddress"))]
    pub mdc_address: Address,
    #[serde(rename(deserialize = "manageAddress"))]
    pub manage_address: Address,
    #[serde(rename(deserialize = "transactionProof"))]
    pub transaction_proof: MerkleAndAnchorProof,
    #[serde(rename(deserialize = "transactionIndex"))]
    pub transaction_index: u64,
    #[serde(rename(deserialize = "mdcRuleProofs"))]
    pub mdc_rule_proofs: MdcRuleProofs,
    /// see [`ObContractStorageConstructor`]
    #[serde(rename(deserialize = "contractsSlotsHash"))]
    pub contracts_slots_hash: [H256; 9],
}

#[derive(Clone, Debug)]
pub struct ProofsRouter {
    pub source: bool,
    pub network: Network,
    pub ethereum_source_proof: Option<EthereumSourceProof>,
    pub ethereum_dest_proof: Option<EthereumDestProof>,
}
