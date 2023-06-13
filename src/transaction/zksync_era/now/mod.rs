use std::{cell::RefCell, env::var};
use std::collections::HashMap;
use std::ops::{Add, Sub};

use ethers_core::types::{Address, Bytes, H160, H256, I256, Transaction, U256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::utils::bit_length;
use itertools::Itertools;
use rlp::{Decodable, Rlp};
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, Network};
use crate::config::token::zksync_era_token::get_zksync_era_eth_address;
use crate::constant::EIP_1559_TX_TYPE_FIELD;
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::AssignedBytes;
use crate::providers::{get_transaction_field_rlp, get_zksync_transaction_and_storage_input};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldWitness};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{FIRST_PHASE, RlcContextPair, RlcTrace};
use crate::util::{bytes_be_to_uint, EthConfigParams};
use crate::util::contract_abi::erc20::{decode_input, is_erc20_transaction};
use crate::util::helpers::{bytes_to_u8, bytes_to_vec_u8, bytes_to_vec_u8_gt_or_lt, get_transaction_type, load_bytes};

mod tests;

#[derive(Clone, Debug)]
pub struct ZkSyncTransactionsInput {
    pub validate_index: u64,
    //This identity starts at 1, if it is 0, it does not work
    pub txs: Vec<Bytes>,
    pub nonce_slots: (H256, H256),
    //pre nonce slot,now nonce slot
    pub amount_slots: Vec<(Address, H256, H256)>,//token address,pre amount slot,now amount slot
}

#[derive(Clone, Debug)]
pub struct ZkSyncTransactionsInputAssigned<F: Field> {
    pub validate_index: AssignedValue<F>,
    pub txs: Vec<AssignedBytes<F>>,
    pub nonce_slots: (AssignedBytes<F>, AssignedBytes<F>),
    pub amount_slots: Vec<(AssignedBytes<F>, AssignedBytes<F>, AssignedBytes<F>)>,
}

impl ZkSyncTransactionsInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ZkSyncTransactionsInputAssigned<F> {
        let validate_index = (F::from(self.validate_index)).try_into().unwrap();
        let validate_index = ctx.load_witness(validate_index);

        let mut load_bytes =
            |bytes: &[u8]| ctx.assign_witnesses(bytes.iter().map(|x| F::from(*x as u64)));

        let txs = self.txs.into_iter().map(|transaction| {
            let tx_rlp = transaction.to_vec();
            load_bytes(&tx_rlp)
        }).collect_vec();

        let nonce_slots = (
            load_bytes(&self.nonce_slots.0.0.to_vec()),
            load_bytes(&self.nonce_slots.1.0.to_vec())
        );

        let amount_slots = self.amount_slots.into_iter().map(|(token_address, pre_amount_slot, now_amount_slot)| {
            (load_bytes(&token_address.0.to_vec()), load_bytes(&pre_amount_slot.0.to_vec()), load_bytes(&now_amount_slot.0.to_vec()))
        }).collect_vec();

        ZkSyncTransactionsInputAssigned { validate_index, txs, nonce_slots, amount_slots }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncBlockTransactionInput {
    pub from_input: ZkSyncTransactionsInput,
    pub to_input: ZkSyncTransactionsInput,
}

#[derive(Clone, Debug)]
pub struct ZkSyncBlockTransactionInputAssigned<F: Field> {
    pub from_input: ZkSyncTransactionsInputAssigned<F>,
    pub to_input: ZkSyncTransactionsInputAssigned<F>,
}

impl ZkSyncBlockTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ZkSyncBlockTransactionInputAssigned<F> {
        let from_input = self.from_input.assign(ctx);
        let to_input = self.to_input.assign(ctx);
        ZkSyncBlockTransactionInputAssigned { from_input, to_input }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncBlockTransactionCircuit {
    pub inputs: ZkSyncBlockTransactionInput,
    pub network: Network,
}

impl ZkSyncBlockTransactionCircuit {
    pub fn from_provider(
        provider: &Provider<Http>,
        tx_hash: H256,
        network: Network,
    ) -> Self {
        let inputs = get_zksync_transaction_and_storage_input(
            provider,
            tx_hash,
        );

        Self { inputs, network }
    }

    pub fn create_circuit<F: Field>(
        self,
        mut builder: RlcThreadBuilder<F>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<F, impl FnSynthesize<F>> {
        let prover = builder.witness_gen_only();
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let chip = EthChip::new(RlpChip::new(&range, None), None);

        let mut keccak = KeccakChip::default();

        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let input = self.inputs.assign(ctx);
        let (witness, digest) = chip.parse_transaction_and_slot_proof_from_block_of_zksync_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input, self.network);

        let EIP1186ResponseDigest {
            index,
            slots_values,
        } = digest;

        let assigned_instances = slots_values
            .into_iter()
            .chain([index])
            .collect_vec();

        let circuit = EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<F>,
                  rlp: RlpChip<F>,
                  keccak_rlcs: (FixedLenRLCs<F>, VarLenRLCs<F>)| {
                // ======== SECOND PHASE ===========
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                let _trace = chip.parse_transaction_and_slot_proof_from_block_of_zksync_phase1(builder, witness);
            },
        );

        #[cfg(not(feature = "production"))]
        if !prover {
            let config_params: EthConfigParams = serde_json::from_str(
                var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
            )
                .unwrap();
            circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
        }
        circuit
    }
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub index: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<AssignedValue<F>>,
}

#[derive(Clone, Debug)]
pub struct TransactionTrace<F: Field> {
    pub nonce_trace: RlcTrace<F>,
    pub gas_price_trace: RlcTrace<F>,
    pub gas_limit_trace: RlcTrace<F>,
    pub to_trace: RlcTrace<F>,
    pub value_trace: RlcTrace<F>,
    pub data_trace: RlcTrace<F>,
    pub v_trace: RlcTrace<F>,
    pub r_trace: RlcTrace<F>,
    pub s_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncTransactionTrace<F: Field> {
    pub from_txs_trace: Vec<TransactionTrace<F>>,
    pub to_txs_trace: Vec<TransactionTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncBlockTransactionTrace<F: Field> {
    pub txs_trace: ZkSyncTransactionTrace<F>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncTransactionTraceWitness<F: Field> {
    from_txs_witness: Vec<RlpArrayTraceWitness<F>>,
    to_txs_witness: Vec<RlpArrayTraceWitness<F>>,
    validate_tx: AssignedBytes<F>,
}

impl<F: Field> ZkSyncTransactionTraceWitness<F> {
    pub fn get_from_txs(&self, transaction_index: usize, transaction_field: &str) -> &RlpFieldWitness<F> {
        match transaction_field {
            "nonce" => &self.from_txs_witness[transaction_index].field_witness[0],
            "gasPrice" => &self.from_txs_witness[transaction_index].field_witness[1],
            "gasLimit" => &self.from_txs_witness[transaction_index].field_witness[2],
            "to" => &self.from_txs_witness[transaction_index].field_witness[3],
            "value" => &self.from_txs_witness[transaction_index].field_witness[4],
            "data" => &self.from_txs_witness[transaction_index].field_witness[5],
            "v" => &self.from_txs_witness[transaction_index].field_witness[6],
            "r" => &self.from_txs_witness[transaction_index].field_witness[7],
            "s" => &self.from_txs_witness[transaction_index].field_witness[8],
            _ => panic!("invalid EIP-2718 transaction field"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncBlockTransactionTraceWitness<F: Field> {
    pub input_witness: ZkSyncTransactionTraceWitness<F>,
}

pub trait ZkSyncBlockTransactionChip<F: Field> {

    // ================= FIRST PHASE ================

    fn parse_transaction_and_slot_proof_from_block_of_zksync_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ZkSyncBlockTransactionInputAssigned<F>,
        network: Network,
    ) -> (ZkSyncBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>);

    fn parse_eip1186_proof_of_zksync_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transactions_and_slots: ZkSyncBlockTransactionInputAssigned<F>,
    ) -> ZkSyncTransactionTraceWitness<F>;

    fn parse_transaction_and_slot_proof_of_zksync_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transactions_and_slots: ZkSyncBlockTransactionInputAssigned<F>,
    ) -> ZkSyncTransactionTraceWitness<F>;


    // ================= SECOND PHASE ================

    fn parse_transaction_and_slot_proof_from_block_of_zksync_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncBlockTransactionTraceWitness<F>,
    ) -> ZkSyncBlockTransactionTrace<F>;

    fn parse_eip1186_proof_of_zksync_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncTransactionTraceWitness<F>,
    ) -> ZkSyncTransactionTrace<F>;

    fn parse_transaction_and_slot_proof_of_zksync_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: ZkSyncTransactionTraceWitness<F>,
    ) -> ZkSyncTransactionTrace<F>;
}

impl<'chip, F: Field> ZkSyncBlockTransactionChip<F> for EthChip<'chip, F> {

    // ================= FIRST PHASE ================

    fn parse_transaction_and_slot_proof_from_block_of_zksync_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ZkSyncBlockTransactionInputAssigned<F>,
        network: Network,
    ) -> (ZkSyncBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>) {
        // let ctx = thread_pool.main(FIRST_PHASE);

        let index = input.from_input.validate_index.try_into().clone().unwrap();

        // drop ctx
        let transactions_witness = self.parse_eip1186_proof_of_zksync_phase0(
            thread_pool,
            keccak,
            input,
        );


        let digest = EIP1186ResponseDigest {
            index,
            slots_values: transactions_witness.validate_tx.to_vec(),
        };

        (ZkSyncBlockTransactionTraceWitness { input_witness: transactions_witness }, digest)
    }

    fn parse_eip1186_proof_of_zksync_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transactions_and_slots: ZkSyncBlockTransactionInputAssigned<F>,
    ) -> ZkSyncTransactionTraceWitness<F> {
        let ctx = thread_pool.main(FIRST_PHASE);
        self.parse_transaction_and_slot_proof_of_zksync_phase0(
            ctx,
            keccak,
            transactions_and_slots,
        )
    }

    fn parse_transaction_and_slot_proof_of_zksync_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transactions_and_slots: ZkSyncBlockTransactionInputAssigned<F>,
    ) -> ZkSyncTransactionTraceWitness<F> {
        let from_validate_index = bytes_to_u8(&transactions_and_slots.from_input.validate_index);
        let from_validate_hash_bytes = transactions_and_slots.from_input.txs.get(from_validate_index as usize).unwrap().clone();

        let to_validate_index = bytes_to_u8(&transactions_and_slots.to_input.validate_index);
        let to_validate_hash_bytes = transactions_and_slots.to_input.txs.get(to_validate_index as usize).unwrap().clone();

        // verify that from_validate_hash_bytes is equal to to_validate_hash_bytes
        for (from_validate_hash, to_validate_hash) in from_validate_hash_bytes.iter().zip(to_validate_hash_bytes.iter()) {
            ctx.constrain_equal(from_validate_hash, to_validate_hash);
        }

        // get transaction info by decode transaction
        let mut get_transaction_info = |transaction: &AssignedBytes<F>| {
            let decode_transaction_rlp_u8 = bytes_to_vec_u8(&transaction.to_vec());
            let decode_transaction = Transaction::decode(&Rlp::new(&decode_transaction_rlp_u8)).unwrap();
            let transaction_from = decode_transaction.recover_from().unwrap();
            let mut transaction_to = Address::default();
            let mut token_address = Address::default();
            let mut token_value = U256::default();
            if !decode_transaction.value.is_zero() {
                transaction_to = decode_transaction.to.unwrap();
                token_address = get_zksync_era_eth_address();
                token_value = decode_transaction.value.clone();
            } else if is_erc20_transaction(decode_transaction.input.clone()) {
                let transaction_erc20 = decode_input(decode_transaction.input.clone()).unwrap();
                transaction_to = transaction_erc20.get(0).unwrap().clone().into_address().unwrap();
                token_address = decode_transaction.to.unwrap();
                token_value = transaction_erc20.get(1).unwrap().clone().into_uint().unwrap();
            }
            (transaction_from, transaction_to, token_address, token_value)
        };

        let (validate_from, validate_to, _, _) = get_transaction_info(&from_validate_hash_bytes.clone());
        let mut get_tx_witness = |txs: Vec<AssignedBytes<F>>, effective_address: Address| {
            let mut effective_txs_witness: Vec<RlpArrayTraceWitness<F>> = vec![];
            let mut amount_map = HashMap::new();
            let txs_witness: Vec<RlpArrayTraceWitness<F>> = txs.iter().map(|transaction| {
                let (transaction_from, transaction_to, token_address, token_value) = get_transaction_info(&transaction.clone());
                let i_token_value = I256::from_raw(token_value);
                let mut amount_diff = I256::default();
                if transaction_from.eq(&effective_address) {// amount-
                    amount_diff = amount_diff.sub(i_token_value);
                } else if transaction_to.eq(&effective_address) { // amount+
                    amount_diff = amount_diff.add(i_token_value);
                }
                if amount_map.contains_key(&token_address) {
                    let mut amount_map_value: I256 = *amount_map.get(&token_address).unwrap();
                    amount_map_value = amount_map_value.add(amount_diff);
                    amount_map.insert(token_address, amount_map_value);
                } else {
                    amount_map.insert(token_address, amount_diff);
                }

                let transaction_rlp_bytes;

                let transaction_value_prefix = transaction.first().unwrap();
                let transaction_type = get_transaction_type(ctx, transaction_value_prefix);

                if transaction_type != 0 {
                    // Todo: Identify nested lists

                    let non_prefix_bytes_u8 = bytes_to_vec_u8(&transaction[1..].to_vec());
                    // Generate rlp encoding for specific fields and generate a witness
                    let dest_value_bytes = get_transaction_field_rlp(transaction_type, &non_prefix_bytes_u8, 12, EIP_1559_TX_TYPE_FIELD);
                    transaction_rlp_bytes = load_bytes(ctx, &dest_value_bytes);
                } else {
                    transaction_rlp_bytes = transaction.to_vec();
                }

                // parse EIP 2718 [nonce,gasPrice,gasLimit,to,value,data,v,r,s]
                let tx_witness = self.rlp().decompose_rlp_array_phase0(
                    ctx,
                    transaction_rlp_bytes,
                    &[32, 32, 32, 20, 32, 100000, 32, 32, 32],//Maximum number of bytes per field. For example, the uint256 is 32 bytes.
                    false,
                );

                // Valid here means that the transaction has an impact on the nonce of the effective_address.
                if transaction_from.eq(&effective_address) {
                    effective_txs_witness.push(tx_witness.clone());
                }

                tx_witness
            })
                .collect();

            (txs_witness, effective_txs_witness, amount_map)
        };

        let (from_txs_witness, from_effective_txs_witness, from_amount_map) = get_tx_witness(transactions_and_slots.from_input.txs.to_vec(), validate_from);
        let (to_txs_witness, to_effective_txs_witness, to_amount_map) = get_tx_witness(transactions_and_slots.to_input.txs.to_vec(), validate_to);

        // compute nonce from big-endian bytes
        let from_nonce_pre = bytes_be_to_uint(ctx, self.gate(), &transactions_and_slots.from_input.nonce_slots.0, 32);
        let from_nonce_now = bytes_be_to_uint(ctx, self.gate(), &transactions_and_slots.from_input.nonce_slots.1, 32);
        let from_nonce_diff = self.gate().sub(ctx, from_nonce_now, from_nonce_pre);
        let to_nonce_pre = bytes_be_to_uint(ctx, self.gate(), &transactions_and_slots.to_input.nonce_slots.0, 32);
        let to_nonce_now = bytes_be_to_uint(ctx, self.gate(), &transactions_and_slots.to_input.nonce_slots.1, 32);
        let to_nonce_diff = self.gate().sub(ctx, to_nonce_now, to_nonce_pre);

        let from_txs_count = (F::from(from_effective_txs_witness.len() as u64)).try_into().unwrap();
        let from_txs_count = ctx.load_witness(from_txs_count);
        ctx.constrain_equal(&from_txs_count, &from_nonce_diff);
        let to_txs_count = (F::from(to_effective_txs_witness.len() as u64)).try_into().unwrap();
        let to_txs_count = ctx.load_witness(to_txs_count);
        ctx.constrain_equal(&to_txs_count, &to_nonce_diff);


        // verify that tx_nonce is equal to expect_nonce
        let mut equal_tx_nonce_to_expect = |txs_witness: &Vec<RlpArrayTraceWitness<F>>, nonce_pre: AssignedValue<F>| {
            if txs_witness.len() != 0 {
                for (tx_index, tx_witness) in txs_witness.iter().enumerate() {
                    let expect_nonce_add_value = (F::from(tx_index as u64)).try_into().unwrap();
                    let expect_nonce_add_value = ctx.load_witness(expect_nonce_add_value);

                    let tx_nonce = &tx_witness.field_witness[0].field_cells;
                    let tx_nonce = bytes_be_to_uint(ctx, self.gate(), tx_nonce, 1);
                    let expect_nonce = self.gate().add(ctx, nonce_pre, expect_nonce_add_value);
                    ctx.constrain_equal(&tx_nonce, &expect_nonce);
                }
            }
        };

        equal_tx_nonce_to_expect(&from_effective_txs_witness, from_nonce_pre);
        equal_tx_nonce_to_expect(&to_effective_txs_witness, to_nonce_pre);

        // calculate account balance changes in line with transaction balance differences.
        let mut get_amount_map_slots = |amount_map: HashMap<H160, I256>| {
            let amount_map_slot: Vec<(AssignedBytes<F>, AssignedValue<F>, AssignedValue<F>)> = amount_map.iter().map(|(token_address, token_value)| {
                let token_address = load_bytes(ctx, &*token_address.0.to_vec());
                let negative = ctx.load_witness(F::from(token_value.is_negative()));
                let token_value = (F::from(token_value.unsigned_abs().as_u64())).try_into().unwrap();
                let token_value = ctx.load_witness(token_value);

                (token_address, token_value, negative)
            })
                .collect();
            amount_map_slot
        };

        let from_amount_map_slots = get_amount_map_slots(from_amount_map);
        let to_amount_map_slots = get_amount_map_slots(to_amount_map);

        let mut equal_tx_amount_to_expect = |amount_slots: &Vec<(AssignedBytes<F>, AssignedBytes<F>, AssignedBytes<F>)>, amount_map_slots: &Vec<(AssignedBytes<F>, AssignedValue<F>, AssignedValue<F>)>| {
            let is_equals: Vec<bool> = amount_slots.iter().map(|(token_address, amount_pre_block_slot, amount_now_block_slot)| {
                let gt_or_lt = bytes_to_vec_u8_gt_or_lt(amount_pre_block_slot, amount_now_block_slot);
                let negative = if gt_or_lt.eq(&1) { true } else if gt_or_lt.eq(&-1) { false } else { true };
                let amount_pre_block_slot = bytes_be_to_uint(ctx, self.gate(), amount_pre_block_slot, 32);
                let amount_now_block_slot = bytes_be_to_uint(ctx, self.gate(), amount_now_block_slot, 32);
                let amount_diff;
                if negative {
                    amount_diff = self.gate().sub(ctx, amount_pre_block_slot, amount_now_block_slot);
                } else {
                    amount_diff = self.gate().sub(ctx, amount_now_block_slot, amount_pre_block_slot);
                };

                let negative = ctx.load_witness(F::from(negative));

                let mut is_equal = false;

                for (slot_token_address, slot_token_amount, slot_value_negative) in amount_map_slots {
                    let gt_or_lt = bytes_to_vec_u8_gt_or_lt(slot_token_address, token_address);
                    if gt_or_lt == 0 {
                        ctx.constrain_equal(slot_token_amount, &amount_diff);
                        ctx.constrain_equal(slot_value_negative, &negative);
                        is_equal = true;
                    }
                };
                is_equal
            })
                .collect();
            assert!(is_equals.contains(&true))
        };

        equal_tx_amount_to_expect(&transactions_and_slots.from_input.amount_slots, &from_amount_map_slots);
        equal_tx_amount_to_expect(&transactions_and_slots.to_input.amount_slots, &to_amount_map_slots);

        ZkSyncTransactionTraceWitness {
            from_txs_witness,
            to_txs_witness,
            validate_tx: from_validate_hash_bytes.to_vec(),
        }
    }


    // ================= SECOND PHASE ================

    fn parse_transaction_and_slot_proof_from_block_of_zksync_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncBlockTransactionTraceWitness<F>,
    ) -> ZkSyncBlockTransactionTrace<F> {
        let txs_trace = self.parse_eip1186_proof_of_zksync_phase1(thread_pool, witness.input_witness);
        ZkSyncBlockTransactionTrace {
            txs_trace
        }
    }

    fn parse_eip1186_proof_of_zksync_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncTransactionTraceWitness<F>,
    ) -> ZkSyncTransactionTrace<F> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let mut get_max_len = |txs_witness: &Vec<RlpArrayTraceWitness<F>>| {
            let len: usize = txs_witness.into_iter().map(|tx_witness| {
                tx_witness.rlp_array.len().pow(5)
            }).sum();
            len
        };

        let from_txs_witness_max_len = get_max_len(&witness.from_txs_witness);
        let to_txs_witness_max_len = get_max_len(&witness.to_txs_witness);

        let max_len = (from_txs_witness_max_len).max(to_txs_witness_max_len);
        let cache_bits = bit_length(max_len as u64);
        println!("cache_bits:{:?}", cache_bits);
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), cache_bits);

        let zksync_transaction_trace = self.parse_transaction_and_slot_proof_of_zksync_phase1((ctx_gate, ctx_rlc), witness);

        zksync_transaction_trace
    }

    fn parse_transaction_and_slot_proof_of_zksync_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: ZkSyncTransactionTraceWitness<F>,
    ) -> ZkSyncTransactionTrace<F> {
        let mut get_transaction_trace = |txs_witness: Vec<RlpArrayTraceWitness<F>>| {
            let transaction_trace: Vec<TransactionTrace<F>> = txs_witness.into_iter().map(|tx_witness| {
                let array_trace: [_; 9] = self
                    .rlp()
                    .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), tx_witness, false)
                    .field_trace
                    .try_into()
                    .unwrap();
                let [
                nonce_trace,
                gas_price_trace,
                gas_limit_trace,
                to_trace,
                value_trace,
                data_trace,
                v_trace,
                r_trace,
                s_trace
                ] =
                    array_trace.map(|trace| trace.field_trace);
                TransactionTrace {
                    nonce_trace,
                    gas_price_trace,
                    gas_limit_trace,
                    to_trace,
                    value_trace,
                    data_trace,
                    v_trace,
                    r_trace,
                    s_trace,
                }
            })
                .collect();
            transaction_trace
        };

        let from_txs_trace = get_transaction_trace(witness.from_txs_witness.to_vec());
        let to_txs_trace = get_transaction_trace(witness.to_txs_witness.to_vec());


        ZkSyncTransactionTrace {
            from_txs_trace,
            to_txs_trace,
        }
    }
}