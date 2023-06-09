#![allow(unused_imports)]

use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{Read, Write},
    iter, num,
    path::Path,
};
use std::ops::{Not, Sub};

use ethers_core::types::{Address, Block, BlockId, BlockId::Number, BlockNumber, Bloom, Bytes, EIP1186ProofResponse, Eip1559TransactionRequest, H256, NameOrAddress, StorageProof, Transaction, U256, U64};
use ethers_core::utils::hex::FromHex;
use ethers_core::utils::keccak256;
use ethers_providers::{Http, Middleware, Provider, StreamExt};
// use halo2_mpt::mpt::{max_branch_lens, max_leaf_lens};
use itertools::Itertools;
use lazy_static::__Deref;
use rlp::{decode, decode_list, Encodable, Rlp, RlpIterator, RlpStream};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::runtime::Runtime;

// until storage proof is refactored
use crate::{
    block_header::ethereum::{
        EthBlockHeaderChainInstance, GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
        MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
    },
    mpt::MPTFixedKeyInput,
    Network,
    storage::{EthBlockStorageInput, EthStorageInput},
    util::{get_merkle_mountain_range, u256_to_bytes32_be},
};
use crate::config::contract::zksync_era_contract::{get_zksync_era_nonce_holder_contract_address, get_zksync_era_nonce_holder_contract_layout};
use crate::config::token::zksync_era_token::{get_zksync_era_eth_address, get_zksync_era_token_layout_by_address};
use crate::mpt::MPTUnFixedKeyInput;
use crate::proof::arbitrum::{ArbitrumProofBlockTrack, ArbitrumProofInput, ArbitrumProofTransactionOrReceipt};
use crate::receipt::arbitrum::{EthBlockReceiptInput as ArbitrumBlockReceiptInput, EthReceiptInput as ArbitrumReceiptInput};
use crate::receipt::ethereum::{EthBlockReceiptInput, EthReceiptInput};
use crate::receipt::optimism::{EthBlockReceiptInput as OptimismBlockReceiptInput, EthReceiptInput as OptimismReceiptInput};
use crate::track_block::EthTrackBlockInput;
use crate::transaction::ethereum::{EthBlockTransactionInput, EthTransactionInput};
use crate::transaction::zksync_era::now::{ZkSyncBlockTransactionInput, ZkSyncTransactionsInput};
use crate::util::contract_abi::erc20::{decode_input, is_erc20_transaction};
use crate::util::helpers::calculate_storage_mapping_key;

const ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN: usize = 114;
const STORAGE_PROOF_VALUE_MAX_BYTE_LEN: usize = 33;

const TRANSACTION_PROOF_VALUE_MAX_BYTE_LEN: usize = 90000;
const RECEIPT_PROOF_VALUE_MAX_BYTE_LEN: usize = 90000;

fn get_buffer_rlp(value: u32) -> Vec<u8> {
    let mut rlp: RlpStream = RlpStream::new();
    rlp.append(&value);
    rlp.out().into()
}

pub fn get_arbitrum_proof(
    arbitrum_provider: &Provider<Http>,
    ethereum_provider: &Provider<Http>,
    l2_seq_num: u64,
    transaction_or_receipt: Vec<ArbitrumProofTransactionOrReceipt>,
    trace_blocks: Vec<ArbitrumProofBlockTrack>,
) -> ArbitrumProofInput {
    let rt = Runtime::new().unwrap();

    let arbitrum_transaction = transaction_or_receipt.get(0).cloned().unwrap();
    let arbitrum_receipt = transaction_or_receipt.get(1).cloned().unwrap();
    let ethereum_transaction = transaction_or_receipt.get(2).cloned().unwrap();
    let arbitrum_trace_block = trace_blocks.get(0).cloned().unwrap();
    let ethereum_trace_block = trace_blocks.get(1).cloned().unwrap();

    let arbitrum_transaction_status = get_block_storage_input_transaction(
        arbitrum_provider,
        arbitrum_trace_block.start_block,
        arbitrum_transaction.index,
        arbitrum_transaction.rlp,
        arbitrum_transaction.merkle_proof,
        arbitrum_transaction.pf_max_depth,
    );

    let arbitrum_receipt_status = get_arbitrum_receipt(
        arbitrum_provider,
        arbitrum_trace_block.start_block,
        arbitrum_receipt.index,
        arbitrum_receipt.rlp,
        arbitrum_receipt.merkle_proof,
        arbitrum_receipt.pf_max_depth,
    );

    let arbitrum_block_end_hash = rt.block_on(arbitrum_provider.get_block(arbitrum_trace_block.end_block)).unwrap().unwrap();
    let mut arbitrum_block_number_interval = vec![];
    for i in arbitrum_trace_block.start_block as u64..arbitrum_block_end_hash.number.unwrap().as_u64() {
        arbitrum_block_number_interval.push(i);
    }
    let arbitrum_block_status = get_block_storage_track(
        arbitrum_provider,
        arbitrum_block_number_interval,
    );

    let ethereum_transaction_status = get_block_storage_input_transaction(
        ethereum_provider,
        ethereum_trace_block.start_block,
        ethereum_transaction.index,
        ethereum_transaction.rlp,
        ethereum_transaction.merkle_proof,
        ethereum_transaction.pf_max_depth,
    );

    let ethereum_block_end_hash = rt.block_on(ethereum_provider.get_block(ethereum_trace_block.end_block)).unwrap().unwrap();
    let mut ethereum_block_number_interval = vec![];
    for i in ethereum_trace_block.start_block as u64..ethereum_block_end_hash.number.unwrap().as_u64() {
        ethereum_block_number_interval.push(i);
    }

    let ethereum_block_status = get_block_storage_track(
        ethereum_provider,
        ethereum_block_number_interval,
    );

    ArbitrumProofInput {
        l2_seq_num,
        arbitrum_transaction_status,
        arbitrum_receipt_status,
        arbitrum_block_status,
        ethereum_transaction_status,
        ethereum_block_status,
    }
}

pub fn get_block_storage_track(
    provider: &Provider<Http>,
    block_number_interval: Vec<u64>,
) -> EthTrackBlockInput {
    let rt = Runtime::new().unwrap();
    let mut block = Vec::with_capacity(block_number_interval.len());
    let mut block_number = Vec::with_capacity(block_number_interval.len());
    let mut block_hash = Vec::with_capacity(block_number_interval.len());
    let mut block_header = Vec::with_capacity(block_number_interval.len());
    for i in block_number_interval {
        let block_element = rt.block_on(provider.get_block(i)).unwrap().unwrap();
        let block_element_hash = block_element.hash.unwrap();
        let block_element_header = get_block_rlp(&block_element);
        block.push(block_element);
        block_number.push(i);
        block_hash.push(block_element_hash);
        block_header.push(block_element_header);
    }

    EthTrackBlockInput {
        block,
        block_number,
        block_hash,
        block_header,
    }
}

pub fn get_block_storage_input_receipt(
    provider: &Provider<Http>,
    block_number: u32,
    receipt_index: u32,
    receipt_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    receipt_pf_max_depth: usize,
) -> EthBlockReceiptInput {
    let rt = Runtime::new().unwrap();
    let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let receipt_key_u256 = U256::from(receipt_index);
    let receipt_key = get_buffer_rlp(receipt_key_u256.as_u32());
    let slot_is_empty = false;

    let receipt_proofs = MPTUnFixedKeyInput {
        path: receipt_key,
        value: receipt_rlp,
        root_hash: block.receipts_root,
        proof: merkle_proof.into_iter().map(|x| x.to_vec()).collect(),
        slot_is_empty,
        value_max_byte_len: RECEIPT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: receipt_pf_max_depth,
    };

    EthBlockReceiptInput {
        block,
        block_number,
        block_hash,
        block_header,
        receipt: EthReceiptInput { receipt_index, receipt_proofs },
    }
}

pub fn get_arbitrum_receipt(
    provider: &Provider<Http>,
    block_number: u32,
    receipt_index: u32,
    receipt_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    receipt_pf_max_depth: usize,
) -> ArbitrumBlockReceiptInput {
    let rt = Runtime::new().unwrap();
    let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let receipt_key_u256 = U256::from(receipt_index);
    let receipt_key = get_buffer_rlp(receipt_key_u256.as_u32());
    let slot_is_empty = false;

    let receipt_proofs = MPTUnFixedKeyInput {
        path: receipt_key,
        value: receipt_rlp,
        root_hash: block.receipts_root,
        proof: merkle_proof.into_iter().map(|x| x.to_vec()).collect(),
        slot_is_empty,
        value_max_byte_len: RECEIPT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: receipt_pf_max_depth,
    };

    ArbitrumBlockReceiptInput {
        block,
        block_number,
        block_hash,
        block_header,
        receipt: ArbitrumReceiptInput { receipt_index, receipt_proofs },
    }
}

pub fn get_optimism_receipt(
    provider: &Provider<Http>,
    block_number: u32,
    receipt_index: u32,
    receipt_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    receipt_pf_max_depth: usize,
) -> OptimismBlockReceiptInput {
    let rt = Runtime::new().unwrap();
    let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let receipt_key_u256 = U256::from(receipt_index);
    let receipt_key = get_buffer_rlp(receipt_key_u256.as_u32());
    let slot_is_empty = false;

    let receipt_proofs = MPTUnFixedKeyInput {
        path: receipt_key,
        value: receipt_rlp,
        root_hash: block.receipts_root,
        proof: merkle_proof.into_iter().map(|x| x.to_vec()).collect(),
        slot_is_empty,
        value_max_byte_len: RECEIPT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: receipt_pf_max_depth,
    };

    OptimismBlockReceiptInput {
        block,
        block_number,
        block_hash,
        block_header,
        receipt: OptimismReceiptInput { receipt_index, receipt_proofs },
    }
}

pub fn get_block_storage_input_transaction(
    provider: &Provider<Http>,
    block_number: u32,
    transaction_index: u32,
    transaction_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    transaction_pf_max_depth: usize,
) -> EthBlockTransactionInput {
    let rt = Runtime::new().unwrap();
    let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
    let block_hash = block.hash.unwrap();
    let block_header = get_block_rlp(&block);
    let transaction_key_u256 = U256::from(transaction_index);
    let transaction_key = get_buffer_rlp(transaction_key_u256.as_u32());
    let slot_is_empty = false;
    let transaction_proofs = MPTUnFixedKeyInput {
        path: transaction_key,
        value: transaction_rlp,
        root_hash: block.transactions_root,
        proof: merkle_proof.into_iter().map(|x| x.to_vec()).collect(),
        slot_is_empty,
        value_max_byte_len: TRANSACTION_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: transaction_pf_max_depth,
    };

    EthBlockTransactionInput {
        block,
        block_number,
        block_hash,
        block_header,
        transaction: EthTransactionInput { transaction_index, transaction_proofs },
    }
}

pub fn get_block_storage_input(
    provider: &Provider<Http>,
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
    let acct_pf = MPTFixedKeyInput {
        path: acct_key,
        value: get_acct_rlp(&pf),
        root_hash: block.state_root,
        proof: pf.account_proof.into_iter().map(|x| x.to_vec()).collect(),
        value_max_byte_len: ACCOUNT_PROOF_VALUE_MAX_BYTE_LEN,
        max_depth: acct_pf_max_depth,
        slot_is_empty,
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
                MPTFixedKeyInput {
                    path,
                    value,
                    root_hash: pf.storage_hash,
                    proof: storage_pf.proof.into_iter().map(|x| x.to_vec()).collect(),
                    value_max_byte_len: STORAGE_PROOF_VALUE_MAX_BYTE_LEN,
                    max_depth: storage_pf_max_depth,
                    slot_is_empty,
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

pub fn get_zksync_transaction_and_storage_input(
    provider: &Provider<Http>,
    tx_hash: H256,
) -> ZkSyncBlockTransactionInput {
    let rt = Runtime::new().unwrap();
    let valid_tx = rt.block_on(provider.get_transaction(tx_hash)).unwrap().unwrap();
    let valid_tx_block_number = valid_tx.block_number.unwrap();
    let block_with_txs = rt.block_on(provider.get_block_with_txs(valid_tx.block_number.unwrap())).unwrap().unwrap();
    let mut valid_tx_from = Address::default();
    let mut valid_tx_to = Address::default();
    // from:valid_tx.from to:valid_tx.to
    if !valid_tx.value.is_zero() { // ETH
        valid_tx_from = valid_tx.from;
        valid_tx_to = valid_tx.to.unwrap();
    } else if is_erc20_transaction(valid_tx.input.clone()) {
        // from:valid_tx.from
        // to:valid_tx.input.to
        let valid_tx_erc20 = decode_input(valid_tx.input.clone()).unwrap();
        valid_tx_from = valid_tx.from;
        valid_tx_to = valid_tx_erc20.get(0).unwrap().clone().into_address().unwrap();
    }

    let mut from_txs: Vec<Bytes> = vec![];
    let mut to_txs: Vec<Bytes> = vec![];
    let mut from_tokens: Vec<Address> = vec![];
    let mut to_tokens: Vec<Address> = vec![];

    for transaction in block_with_txs.transactions {
        let transaction_from = transaction.from;
        let transaction_to = transaction.to.unwrap();
        let transaction_value = transaction.value;

        // ETH
        if !transaction_value.is_zero() {
            // out \ in
            if transaction_from == valid_tx_from || transaction_to == valid_tx_from {
                from_txs.push(transaction.rlp());
                if !from_tokens.contains(&get_zksync_era_eth_address()) {
                    from_tokens.push(get_zksync_era_eth_address());
                }
            }
            if transaction_from == valid_tx_to || transaction_to == valid_tx_to {
                // out \ in
                to_txs.push(transaction.rlp());
                if !to_tokens.contains(&get_zksync_era_eth_address()) {
                    to_tokens.push(get_zksync_era_eth_address());
                }
            }
        } else if is_erc20_transaction(transaction.input.clone()) {//非ETH交易
            let erc20_address = transaction.to.unwrap();
            let transaction_erc20 = decode_input(transaction.input.clone()).unwrap();
            let transaction_erc20_to = transaction_erc20.get(0).unwrap().clone().into_address().unwrap();
            // out \ in
            if transaction_from == valid_tx_from || transaction_erc20_to == valid_tx_from {
                from_txs.push(transaction.rlp());
                if !from_tokens.contains(&erc20_address) {
                    from_tokens.push(erc20_address);
                }
            }
            if transaction_from == valid_tx_to || transaction_erc20_to == valid_tx_to {
                to_txs.push(transaction.rlp());
                if !to_tokens.contains(&erc20_address) {
                    to_tokens.push(erc20_address);
                }
            }
        }
    }

    let from_validate_index = from_txs.iter().position(|tx_rlp|tx_rlp.clone()==valid_tx.rlp()).unwrap();
    let to_validate_index = to_txs.iter().position(|tx_rlp|tx_rlp.clone()==valid_tx.rlp()).unwrap();

    let pre_block_id = Option::from(BlockId::from(valid_tx_block_number.sub(1)));
    let now_block_id = Option::from(BlockId::from(valid_tx_block_number));

    let from_nonce_location = calculate_storage_mapping_key(get_zksync_era_nonce_holder_contract_layout(), valid_tx_from);
    let to_nonce_location = calculate_storage_mapping_key(get_zksync_era_nonce_holder_contract_layout(), valid_tx_to);

    let from_nonce_slots = (
        rt.block_on(provider.get_storage_at(get_zksync_era_nonce_holder_contract_address(), from_nonce_location, pre_block_id)).unwrap(),
        rt.block_on(provider.get_storage_at(get_zksync_era_nonce_holder_contract_address(), from_nonce_location, now_block_id)).unwrap()
    );

    let to_nonce_slots=(
        rt.block_on(provider.get_storage_at(get_zksync_era_nonce_holder_contract_address(), to_nonce_location, pre_block_id)).unwrap(),
        rt.block_on(provider.get_storage_at(get_zksync_era_nonce_holder_contract_address(), to_nonce_location, now_block_id)).unwrap()
    );

    let mut get_amount_slots = |tokens:Vec<Address>,storage_key:Address|{
        let amount_slots:Vec<(Address,H256,H256)> = tokens.into_iter().map(|token_address|{
            let token_layout = get_zksync_era_token_layout_by_address(token_address).unwrap();
            let token_location = calculate_storage_mapping_key(token_layout, storage_key);
            let to_amount_pre_block_slot = rt.block_on(provider.get_storage_at(token_address, token_location, pre_block_id)).unwrap();
            let to_amount_now_block_slot = rt.block_on(provider.get_storage_at(token_address, token_location, now_block_id)).unwrap();
            (token_address,to_amount_pre_block_slot, to_amount_now_block_slot)
        })
            .collect();
        amount_slots
    };

    let from_amount_slots =get_amount_slots(from_tokens,valid_tx_from);
    let to_amount_slots =get_amount_slots(to_tokens,valid_tx_to);

    ZkSyncBlockTransactionInput {
        from_input: ZkSyncTransactionsInput {
            validate_index: from_validate_index as u64,
            txs: from_txs,
            nonce_slots: from_nonce_slots,
            amount_slots: from_amount_slots,
        },
        to_input: ZkSyncTransactionsInput {
            validate_index: to_validate_index as u64,
            txs: to_txs,
            nonce_slots: to_nonce_slots,
            amount_slots: to_amount_slots,
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

// EIP_2718 [nonce,gasPrice,gasLimit,to,value,data,v,r,s]
// 1: EIP_2930 [chainId,nonce,gasPrice,gasLimit,to,value,data,accessList,v,r,s]
// 2: EIP_1559 [chainId,nonce,maxPriorityFeePerGas,maxFeePerGas,gasLimit,to,value,data,accessList,v,r,s]
pub fn get_transaction_field_rlp(tx_type: usize, source: &Vec<u8>, item_count: usize, new_item: [u8; 9]) -> Vec<u8> {
    let mut source_rlp = RlpStream::new();
    source_rlp.append_raw(source, item_count);
    let source_bytes = source_rlp.as_raw().to_vec();
    let rlp = Rlp::new(&source_bytes);
    let mut dest_rlp = RlpStream::new_list(new_item.len());
    for field_item in new_item {
        let field_rlp = rlp.at_with_offset(field_item as usize).unwrap();
        let field = field_rlp.0.data().unwrap();
        if tx_type == 2 {
            match field_item {
                0 => {
                    let dest_field = U64::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                1 => {
                    let dest_field = U256::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                2 => {
                    let dest_field = U256::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                3 => {
                    let dest_field = U256::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                4 => {
                    let dest_field = U256::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                5 => {
                    let dest_field = NameOrAddress::Address(Address::from_slice(field));
                    dest_rlp.append(&dest_field);
                }
                6 => {
                    let dest_field = U256::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                7 => {
                    let dest_field = Bytes::from(field.to_vec()).clone();
                    let a = dest_field.0.to_vec();
                    dest_rlp.append(&a);
                }
                9 => {
                    let dest_field = U64::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                10 => {
                    let dest_field = U256::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                11 => {
                    let dest_field = U256::from_big_endian(field);
                    dest_rlp.append(&dest_field);
                }
                _ => println!("error")
            }
        }
    }

    dest_rlp.out().into()
}

pub fn get_receipt_field_rlp(source: &Vec<u8>, item_count: usize, new_item: [u8; 3]) -> Vec<u8> {
    let mut source_rlp = RlpStream::new();
    source_rlp.append_raw(source, item_count);
    let source_bytes = source_rlp.as_raw().to_vec();
    let rlp = Rlp::new(&source_bytes);
    let mut dest_rlp = RlpStream::new_list(new_item.len());
    for field_item in new_item {
        let field_rlp = rlp.at_with_offset(field_item as usize).unwrap();
        let field = field_rlp.0.data().unwrap();
        match field_item {
            0 => {
                let dest_field = U64::from_big_endian(field);
                dest_rlp.append(&dest_field);
            }
            1 => {
                let dest_field = U64::from_big_endian(field);
                dest_rlp.append(&dest_field);
            }
            2 => {
                let dest_field = Bloom::from_slice(field);
                dest_rlp.append(&dest_field);
            }
            _ => panic!()
        }
    }

    dest_rlp.out().into()
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
    let withdrawals_root: Option<H256> =
        block.other.get_deserialized("withdrawalsRoot").and_then(|x| x.ok());
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
    rlp.out().into()
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
    provider: &Provider<Http>,
    start_block_number: u32,
    num_blocks: u32,
    max_depth: usize,
) -> (Vec<Vec<u8>>, EthBlockHeaderChainInstance) {
    assert!(num_blocks <= (1 << max_depth));
    fs::create_dir_all("./data/headers").unwrap();
    let end_block_number = start_block_number + num_blocks - 1;
    let rt = Runtime::new().unwrap();
    let chain_id = rt.block_on(provider.get_chainid()).unwrap();
    let path = format!(
        "./data/headers/chainid{chain_id}_{start_block_number:06x}_{end_block_number:06x}.json"
    );

    let ProcessedBlock { mut block_rlps, block_hashes, prev_hash } =
        if let Ok(f) = File::open(path.as_str()) {
            serde_json::from_reader(f).unwrap()
        } else {
            let mut block_rlps = Vec::with_capacity(max_depth);
            let mut block_hashes = Vec::with_capacity(num_blocks as usize);
            let mut prev_hash = H256::zero();

            for block_number in start_block_number..start_block_number + num_blocks {
                let block = rt
                    .block_on(provider.get_block(block_number as u64))
                    .expect("get_block JSON-RPC call")
                    .unwrap_or_else(|| panic!("block {block_number} should exist"));
                if block_number == start_block_number {
                    prev_hash = block.parent_hash;
                }
                block_hashes.push(block.hash.unwrap());
                block_rlps.push(get_block_rlp(&block));
            }
            // write this to file
            let file = File::create(path.as_str()).unwrap();
            let payload = ProcessedBlock { block_rlps, block_hashes, prev_hash };
            serde_json::to_writer(file, &payload).unwrap();
            payload
        };
    // pad to correct length with dummies
    let dummy_block_rlp = block_rlps[0].clone();
    block_rlps.resize(1 << max_depth, dummy_block_rlp);

    let end_hash = *block_hashes.last().unwrap();
    let mmr = get_merkle_mountain_range(&block_hashes, max_depth);

    let instance = EthBlockHeaderChainInstance::new(
        prev_hash,
        end_hash,
        start_block_number,
        end_block_number,
        mmr,
    );
    (block_rlps, instance)
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
