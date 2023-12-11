#![allow(unused_imports)]

use std::ops::{Mul, Not, Range, Sub};
use std::path::PathBuf;
use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{Read, Write},
    iter, num,
    path::Path,
};

use ethers_core::types::{
    Address, Block, BlockId, BlockId::Number, BlockNumber, Bloom, Bytes, EIP1186ProofResponse,
    Eip1559TransactionRequest, NameOrAddress, StorageProof, Transaction, H256, U256, U64,
};
use ethers_core::utils::hex::FromHex;
use ethers_core::utils::keccak256;
use ethers_providers::{Http, Middleware, Provider, ProviderError, RetryClient, StreamExt};
use futures::future::{join, join_all};
use itertools::Itertools;
use lazy_static::__Deref;
use rlp::{decode, decode_list, Decodable, Encodable, Rlp, RlpIterator, RlpStream};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::runtime::Runtime;

use crate::block_header::zksync_era::{
    ZkSyncEraBlockHeaderInput, ZkSyncEraBlockHeadersInput, BLOCK_INCLUDE_TXS_MAX_NUMBER,
};
use crate::ecdsa::util::recover_tx_info;
use crate::ecdsa::EthEcdsaInput;
use crate::mpt::MPTInput;
use crate::receipt::{EthBlockReceiptInput, EthReceiptInput, RECEIPT_MAX_LEN};
use crate::storage::contract_storage::util::MultiBlocksContractsStorageConstructor;
use crate::storage::contract_storage::{
    BlockInput, ObContractsStorageBlockInput, ObContractsStorageInput,
    EBC_RULE_PROOF_VALUE_MAX_BYTE_LEN,
};
use crate::storage::{
    EbcRuleVersion, ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN, STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
};
use crate::track_block::util::TrackBlockConstructor;
use crate::track_block::EthTrackBlockInput;
use crate::transaction::ethereum::{EthBlockTransactionInput, EthTransactionInput};
use crate::transaction::zksync_era::{ZkSyncEraBlockTransactionInput, ZkSyncEraTransactionInput};
use crate::transaction::{calculate_tx_max_len, TX_MAX_LEN};
use crate::util::contract_abi::erc20::{decode_input, is_erc20_transaction};
use crate::util::helpers::calculate_storage_mapping_key;
use crate::util::{
    h256_non_standard_tree_root_and_proof, h256_tree_root, h256_tree_root_and_proof,
    h256_tree_verify,
};
use crate::{
    storage::{EthBlockStorageInput, EthStorageInput},
    util::{get_merkle_mountain_range, u256_to_bytes32_be},
    Network,
};

const TRANSACTION_INDEX_MAX_KEY_BYTES_LEN: usize = 3;
const K256_MAX_KEY_BYTES_LEN: usize = 32;

pub fn get_batch_block_merkle_root(
    provider: &Provider<RetryClient<Http>>,
    start_block_num: u32,
    end_block_num: u32,
    block_verify_index: u32,
) {
    let rt = Runtime::new().unwrap();
    assert!(start_block_num <= end_block_num);
    let mut leaves = Vec::with_capacity((end_block_num - start_block_num) as usize);
    let merkle_verify_leaf_index = block_verify_index - start_block_num;
    for block_num in start_block_num..=end_block_num {
        let block = rt.block_on(provider.get_block(block_num as u64)).unwrap().unwrap();
        let block_hash = block.hash.unwrap();
        leaves.push(block_hash);
    }
    let (proof_root, proof, path) =
        h256_non_standard_tree_root_and_proof(&leaves, merkle_verify_leaf_index);

    h256_tree_verify(&proof_root, &leaves[merkle_verify_leaf_index as usize], &proof, &path);
}

fn get_buffer_rlp(value: u32) -> Vec<u8> {
    let mut rlp: RlpStream = RlpStream::new();
    rlp.append(&value);
    rlp.out().into()
}

pub fn get_block_track_input(
    provider: &Provider<RetryClient<Http>>,
    constructor: &TrackBlockConstructor,
) -> EthTrackBlockInput {
    let rt = Runtime::new().unwrap();
    let blocks_number = constructor.blocks_number.clone();
    let mut block = Vec::with_capacity(blocks_number.len());
    let mut block_number = Vec::with_capacity(blocks_number.len());
    let mut block_hash = Vec::with_capacity(blocks_number.len());
    let mut block_header = Vec::with_capacity(blocks_number.len());
    for i in blocks_number.clone() {
        let block_element = rt.block_on(provider.get_block(i)).unwrap().unwrap();
        let block_element_hash = block_element.hash.unwrap();
        let block_element_header = get_block_rlp(&block_element);
        block.push(block_element);
        block_number.push(i);
        block_hash.push(block_element_hash);
        block_header.push(block_element_header);
    }

    EthTrackBlockInput { block, block_number, block_hash, block_header }
}

//
pub fn get_receipt_input(
    provider: &Provider<RetryClient<Http>>,
    transaction_hash: H256,
    receipt_index_bytes: Option<Vec<u8>>,
    receipt_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    receipt_pf_max_depth: usize,
) -> EthBlockReceiptInput {
    let rt = Runtime::new().unwrap();
    let tx = rt.block_on(provider.get_transaction(transaction_hash)).unwrap().unwrap();
    let receipt_index = tx.transaction_index.unwrap().as_u64();
    let block_number = tx.block_number.unwrap().as_u64();
    let block = rt.block_on(provider.get_block(block_number)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let receipt_key =
        receipt_index_bytes.unwrap_or(get_buffer_rlp(U256::from(receipt_index).as_u32()));
    let slot_is_empty = false;

    let receipt_proofs = MPTInput {
        path: (&receipt_key).into(),
        value: receipt_rlp,
        root_hash: block.receipts_root,
        proof: merkle_proof.into_iter().map(|x| x.to_vec()).collect(),
        slot_is_empty,
        value_max_byte_len: RECEIPT_MAX_LEN,
        max_depth: receipt_pf_max_depth,
        max_key_byte_len: TRANSACTION_INDEX_MAX_KEY_BYTES_LEN,
        key_byte_len: Some(receipt_key.len()),
    };

    EthBlockReceiptInput {
        block,
        block_number,
        block_hash,
        block_header,
        receipt: EthReceiptInput { receipt_index, receipt_proofs },
    }
}

pub fn get_transaction_input(
    provider: &Provider<RetryClient<Http>>,
    transaction_hash: H256,
    transaction_index_bytes: Option<Vec<u8>>,
    transaction_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    transaction_pf_max_depth: usize,
) -> EthBlockTransactionInput {
    let rt = Runtime::new().unwrap();
    let tx = rt.block_on(provider.get_transaction(transaction_hash)).unwrap().unwrap();
    let transaction_index = tx.transaction_index.unwrap().as_u64();
    let block_number = tx.block_number.unwrap().as_u64();
    let block = rt.block_on(provider.get_block(block_number)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let transaction_key =
        transaction_index_bytes.unwrap_or(get_buffer_rlp(U256::from(transaction_index).as_u32()));
    let slot_is_empty = false;
    let transaction_proofs = MPTInput {
        path: (&transaction_key).into(),
        value: transaction_rlp.to_vec(),
        root_hash: block.transactions_root,
        proof: merkle_proof.into_iter().map(|x| x.to_vec()).collect(),
        slot_is_empty,
        value_max_byte_len: calculate_tx_max_len(transaction_rlp.to_vec().len()),
        max_depth: transaction_pf_max_depth,
        max_key_byte_len: TRANSACTION_INDEX_MAX_KEY_BYTES_LEN,
        key_byte_len: Some(transaction_key.len()),
    };

    let transaction = Transaction::decode(&Rlp::new(&transaction_rlp)).unwrap();
    let (signature, message, message_hash, public_key) = recover_tx_info(&transaction);
    EthBlockTransactionInput {
        block,
        block_number,
        block_hash,
        block_header,
        transaction: EthTransactionInput {
            transaction_index,
            transaction_proofs,
            transaction_ecdsa_verify: EthEcdsaInput {
                signature,
                message,
                message_hash,
                public_key,
            },
        },
    }
}

pub fn get_storage_input(
    provider: &Provider<RetryClient<Http>>,
    block_number: u32,
    addr: Address,
    slots: Vec<H256>,
    acct_pf_max_depth: usize,
    storage_pf_max_depth: usize,
) -> EthBlockStorageInput {
    let rt = Runtime::new().unwrap();
    let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);

    let pf = rt
        .block_on(provider.get_proof(addr, slots, Some(Number(BlockNumber::from(block_number)))))
        .unwrap();

    let acct_key = H256(keccak256(addr));
    let slot_is_empty = !is_assigned_slot(&acct_key, &pf.account_proof);
    let acct_pf = MPTInput {
        path: acct_key.into(),
        value: get_acct_rlp(&pf),
        root_hash: block.state_root,
        proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
        value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: acct_pf_max_depth,
        max_key_byte_len: K256_MAX_KEY_BYTES_LEN,
        slot_is_empty,
        key_byte_len: None,
    };

    let storage_pfs = pf
        .storage_proof
        .into_iter()
        .map(|storage_pf| {
            let path = H256(keccak256(storage_pf.key));
            let slot_is_empty = !is_assigned_slot(&path, &storage_pf.proof);
            let value =
                if slot_is_empty { vec![0u8] } else { storage_pf.value.rlp_bytes().to_vec() };
            (
                storage_pf.key,
                storage_pf.value,
                MPTInput {
                    path: path.into(),
                    value,
                    root_hash: pf.storage_hash,
                    proof: storage_pf.proof.into_iter().map(|x| x.to_vec()).collect(),
                    value_max_byte_len: STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
                    max_depth: storage_pf_max_depth,
                    max_key_byte_len: K256_MAX_KEY_BYTES_LEN,
                    slot_is_empty,
                    key_byte_len: None,
                },
            )
        })
        .collect();

    EthBlockStorageInput {
        block,
        block_number,
        block_hash,
        block_header,
        storage: EthStorageInput { addr, acct_pf, storage_pfs },
    }
}

pub fn get_contract_storage_input(
    provider: &Provider<RetryClient<Http>>,
    constructor: MultiBlocksContractsStorageConstructor,
) -> ObContractsStorageBlockInput {
    let rt = Runtime::new().unwrap();
    let blocks_contracts_storage = constructor
        .blocks_contracts_storage
        .into_iter()
        .map(|constructor| {
            let block_number = constructor.block_number;
            let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
            let block_hash = block.hash.unwrap();
            let block_header = get_block_rlp(&block);

            let block_contracts_storage = constructor
                .block_contracts_storage
                .into_iter()
                .map(|c| {
                    let address = c.contract_address;
                    let slots = c.slots;

                    let pf = rt
                        .block_on(provider.get_proof(
                            address,
                            slots,
                            Some(Number(BlockNumber::from(block_number))),
                        ))
                        .unwrap();

                    let acct_key = H256(keccak256(address));
                    let slot_is_empty = !is_assigned_slot(&acct_key, &pf.account_proof);
                    let acct_pf = MPTInput {
                        path: acct_key.into(),
                        value: get_acct_rlp(&pf),
                        root_hash: block.state_root,
                        proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
                        value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
                        max_depth: c.acct_pf_max_depth,
                        max_key_byte_len: K256_MAX_KEY_BYTES_LEN,
                        slot_is_empty,
                        key_byte_len: None,
                    };

                    let storage_pfs = pf
                        .storage_proof
                        .into_iter()
                        .map(|storage_pf| {
                            let path = H256(keccak256(storage_pf.key));
                            let slot_is_empty = !is_assigned_slot(&path, &storage_pf.proof);
                            let value = if slot_is_empty {
                                vec![0u8]
                            } else {
                                storage_pf.value.rlp_bytes().to_vec()
                            };
                            (
                                storage_pf.key,
                                storage_pf.value,
                                MPTInput {
                                    path: path.into(),
                                    value,
                                    root_hash: pf.storage_hash,
                                    proof: storage_pf
                                        .proof
                                        .into_iter()
                                        .map(|x| x.to_vec())
                                        .collect(),
                                    value_max_byte_len: STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
                                    max_depth: c.storage_pf_max_depth,
                                    max_key_byte_len: K256_MAX_KEY_BYTES_LEN,
                                    slot_is_empty,
                                    key_byte_len: None,
                                },
                            )
                        })
                        .collect();

                    EthStorageInput { addr: address, acct_pf, storage_pfs }
                })
                .collect();

            let block_input = BlockInput { block, block_number, block_hash, block_header };

            let ob_contracts_storage_input = ObContractsStorageInput {
                contracts_storage: block_contracts_storage, // mdc ,manage
            };
            (block_input, ob_contracts_storage_input)
        })
        .collect();
    let ebc_rule_params = constructor.ebc_rule_params;

    // ebc mpt
    let mut ebc_rule_pfs;
    {
        let path = ebc_rule_params.ebc_rule_key;
        let value = ebc_rule_params.ebc_rule_value.to_vec();
        ebc_rule_pfs = MPTInput {
            path: path.into(),
            value,
            root_hash: ebc_rule_params.ebc_rule_root,
            proof: ebc_rule_params.ebc_rule_merkle_proof.into_iter().map(|x| x.to_vec()).collect(),
            slot_is_empty: false,
            value_max_byte_len: EBC_RULE_PROOF_VALUE_MAX_BYTE_LEN,
            max_depth: ebc_rule_params.ebc_rule_pf_max_depth,
            max_key_byte_len: K256_MAX_KEY_BYTES_LEN,
            key_byte_len: None,
        }
    }

    ObContractsStorageBlockInput {
        contract_storage_block: blocks_contracts_storage,
        ebc_rules_pfs: ebc_rule_pfs,
    }
}

pub fn get_zksync_era_block_with_txs_input(
    provider: &Provider<RetryClient<Http>>,
    blocks_number: Vec<u64>,
) -> ZkSyncEraBlockHeadersInput {
    let rt = Runtime::new().unwrap();
    let headers = blocks_number
        .into_iter()
        .map(|block_number| {
            let block = rt.block_on(provider.get_block(block_number)).unwrap().unwrap();
            ZkSyncEraBlockHeaderInput {
                block_header: get_zksync_era_block_rlp(&block),
                txs_hash: block.transactions,
                max_txs_len: BLOCK_INCLUDE_TXS_MAX_NUMBER,
            }
        })
        .collect_vec();
    ZkSyncEraBlockHeadersInput { headers }
}

pub fn get_zksync_era_transaction_input(
    provider: &Provider<RetryClient<Http>>,
    tx_hash: H256,
) -> ZkSyncEraBlockTransactionInput {
    let rt = Runtime::new().unwrap();
    let tx = rt.block_on(provider.get_transaction(tx_hash)).unwrap().unwrap();
    let tx_status = rt.block_on(provider.get_transaction_receipt(tx_hash)).unwrap().unwrap();
    let block_headers_input =
        get_zksync_era_block_with_txs_input(provider, vec![tx.block_number.unwrap().as_u64()]);
    let block_header = block_headers_input.headers.get(0).unwrap().clone();
    let transaction = Transaction::decode(&Rlp::new(&tx.rlp().to_vec())).unwrap();
    let (signature, message, message_hash, public_key) = recover_tx_info(&transaction);
    ZkSyncEraBlockTransactionInput {
        block_header,
        transaction: ZkSyncEraTransactionInput {
            transaction_index: tx.transaction_index.unwrap().as_u64(),
            transaction_status: tx_status.status.unwrap().as_u64(),
            transaction_value: tx.rlp().to_vec(),
            transaction_value_max_bytes: calculate_tx_max_len(tx.rlp().len()),
            transaction_ecdsa_verify: EthEcdsaInput {
                signature,
                message,
                message_hash,
                public_key,
            },
        },
    }
}

pub fn is_assigned_slot(key: &H256, proof: &[Bytes]) -> bool {
    let mut key_nibbles = Vec::new();
    for &byte in key.as_bytes() {
        key_nibbles.push(byte / 16);
        key_nibbles.push(byte % 16);
    }
    let mut key_frags = Vec::new();
    let mut path_idx = 0;
    for node in proof.iter() {
        let rlp = Rlp::new(node);
        if rlp.item_count().unwrap() == 2 {
            let path = rlp.at(0).unwrap().data().unwrap();
            let is_odd = (path[0] / 16 == 1u8) || (path[0] / 16 == 3u8);
            let mut frag = Vec::new();
            if is_odd {
                frag.push(path[0] % 16);
                path_idx += 1;
            }
            for byte in path.iter().skip(1) {
                frag.push(*byte / 16);
                frag.push(*byte % 16);
                path_idx += 2;
            }
            key_frags.extend(frag);
        } else {
            key_frags.extend(vec![key_nibbles[path_idx]]);
            path_idx += 1;
        }
    }
    if path_idx == 64 {
        for idx in 0..64 {
            if key_nibbles[idx] != key_frags[idx] {
                return false;
            }
        }
    } else {
        return false;
    }
    true
}

pub fn get_acct_rlp(pf: &EIP1186ProofResponse) -> Vec<u8> {
    let mut rlp: RlpStream = RlpStream::new_list(4);
    rlp.append(&pf.nonce);
    rlp.append(&pf.balance);
    rlp.append(&pf.storage_hash);
    rlp.append(&pf.code_hash);
    rlp.out().into()
}

pub fn get_block_rlp(block: &Block<H256>) -> Vec<u8> {
    let withdrawals_root: Option<H256> = block.withdrawals_root;
    let base_fee = block.base_fee_per_gas;
    let rlp_len = 15 + usize::from(base_fee.is_some()) + usize::from(withdrawals_root.is_some());
    let mut rlp = RlpStream::new_list(rlp_len);
    rlp.append(&block.parent_hash);
    rlp.append(&block.uncles_hash);
    rlp.append(&block.author.unwrap());
    rlp.append(&block.state_root);
    rlp.append(&block.transactions_root);
    rlp.append(&block.receipts_root);
    rlp.append(&block.logs_bloom.unwrap());
    rlp.append(&block.difficulty);
    rlp.append(&block.number.unwrap());
    rlp.append(&block.gas_limit);
    rlp.append(&block.gas_used);
    rlp.append(&block.timestamp);
    rlp.append(&block.extra_data.to_vec());
    rlp.append(&block.mix_hash.unwrap());
    rlp.append(&block.nonce.unwrap());
    base_fee.map(|base_fee| rlp.append(&base_fee));
    withdrawals_root.map(|withdrawals_root| rlp.append(&withdrawals_root));
    let encoding: Vec<u8> = rlp.out().into();
    assert_eq!(keccak256(&encoding), block.hash.unwrap().0);
    encoding
}

pub fn get_zksync_era_block_rlp(block: &Block<H256>) -> Vec<u8> {
    let mut rlp = RlpStream::new_list(3);

    rlp.append(&block.number.unwrap());
    rlp.append(&block.timestamp);
    rlp.append(&block.parent_hash);

    let encoding: Vec<u8> = rlp.out().into();
    encoding
}

serde_with::serde_conv!(
    BytesBase64,
    Vec<u8>,
    |bytes: &Vec<u8>| {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.encode(bytes)
    },
    |encoded: String| {
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD.decode(encoded)
    }
);

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessedBlock {
    #[serde_as(as = "Vec<BytesBase64>")]
    pub block_rlps: Vec<Vec<u8>>,
    pub block_hashes: Vec<H256>,
    pub prev_hash: H256,
}

/// returns tuple of:
///   * vector of RLP bytes of each block
///   * tuple of
///       * parentHash (H256)
///       * endHash (H256)
///       * startBlockNumber (u32)
///       * endBlockNumber (u32)
///       * merkleRoots (Vec<H256>)
///   * where merkleRoots is a length `max_depth + 1` vector representing a merkle mountain range, ordered largest mountain first
// second tuple `instance` is only used for debugging now
pub fn get_blocks_input(
    provider: &Provider<RetryClient<Http>>,
    start_block_number: u32,
    num_blocks: u32,
    max_depth: usize,
) -> Vec<Vec<u8>> {
    assert!(num_blocks <= (1 << max_depth));
    assert!(num_blocks > 0);
    let chain_data_dir = PathBuf::from("data/chain");
    fs::create_dir_all(&chain_data_dir).unwrap();
    let end_block_number = start_block_number + num_blocks - 1;
    let rt = Runtime::new().unwrap();
    let chain_id = rt.block_on(provider.get_chainid()).unwrap();
    let path = chain_data_dir
        .join(format!("chainid{chain_id}_{start_block_number:06x}_{end_block_number:06x}.json"));
    // block_hashes and prev_hash no longer used, but keeping this format for compatibility with old cached chaindata
    let ProcessedBlock { mut block_rlps, block_hashes: _, prev_hash: _ } =
        if let Ok(f) = File::open(&path) {
            serde_json::from_reader(f).unwrap()
        } else {
            let blocks = get_blocks(
                provider,
                start_block_number as u64..(start_block_number + num_blocks) as u64,
            )
            .unwrap_or_else(|e| panic!("get_blocks JSON-RPC call failed: {e}"));
            let prev_hash = blocks[0].as_ref().expect("block not found").parent_hash;
            let (block_rlps, block_hashes): (Vec<_>, Vec<_>) = blocks
                .into_iter()
                .map(|block| {
                    let block = block.expect("block not found");
                    (get_block_rlp(&block), block.hash.unwrap())
                })
                .unzip();
            // write this to file
            let file = File::create(&path).unwrap();
            let payload = ProcessedBlock { block_rlps, block_hashes, prev_hash };
            serde_json::to_writer(file, &payload).unwrap();
            payload
        };
    // pad to correct length with dummies
    let dummy_block_rlp = block_rlps[0].clone();
    block_rlps.resize(1 << max_depth, dummy_block_rlp);
    block_rlps
}

pub fn get_blocks(
    provider: &Provider<RetryClient<Http>>,
    block_numbers: impl IntoIterator<Item = u64>,
) -> Result<Vec<Option<Block<H256>>>, ProviderError> {
    let rt = Runtime::new().unwrap();
    rt.block_on(join_all(
        block_numbers.into_iter().map(|block_number| provider.get_block(block_number)),
    ))
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use std::env::var;

    use super::*;

    #[test]
    fn test_infura() {
        let infura_id = var("INFURA_ID").expect("Infura ID not found");
        let provider = Provider::<Http>::try_from(
            format!("https://mainnet.infura.io/v3/{infura_id}").as_str(),
        )
        .expect("could not instantiate HTTP Provider");

        let rt = Runtime::new().unwrap();
        let block = rt.block_on(provider.get_block(17034973)).unwrap().unwrap();
        get_block_rlp(&block);
    }
}
