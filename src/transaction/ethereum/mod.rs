use ethers_core::abi::AbiEncode;
use std::cell::RefCell;
use std::f32::consts::E;

use ethers_core::types::{Block, Bytes, H256};
use ethers_providers::{Http, Provider};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::{AssignedValue, Context};
use hex::FromHex;
use itertools::Itertools;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use zkevm_keccak::util::eth_types::Field;

use crate::block_header::{
    get_block_header_config, BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace,
    EthBlockHeaderTraceWitness,
};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{AssignedBytes, MPTInput, MPTProof, MPTProofWitness};
use crate::providers::get_transaction_input;
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{RlcContextPair, FIRST_PHASE};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness};
use crate::storage::EthStorageChip;
use crate::transaction::ethereum::util::TransactionConstructor;
use crate::transaction::{
    load_transaction_type, EIP_1559_TX_TYPE_FIELDS_MAX_FIELDS_LEN, EIP_2718_TX_TYPE,
    EIP_2718_TX_TYPE_FIELDS_MAX_FIELDS_LEN, EIP_TX_TYPE_CRITICAL_VALUE, TX_MAX_LEN,
};
use crate::util::helpers::load_bytes;
use crate::util::{
    bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, encode_h256_to_field, AssignedH256,
};
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, Network, ETH_LOOKUP_BITS};

pub mod helper;
pub mod tests;
pub mod util;

// lazy_static! {
//     static ref KECCAK_RLP_EMPTY_STRING: Vec<u8> =
//         Vec::from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
// }

const NUM_BITS: usize = 8;

const FUNCTION_SELECTOR_BYTES_LEN: usize = 4;
const ERC20_TO_ADDRESS_BYTES_LEN: usize = 32;
const ERC20_AMOUNT_BYTES_LEN: usize = 32;
const FUNCTION_SELECTOR_ERC20_TRANSFER: [u8; FUNCTION_SELECTOR_BYTES_LEN] = [169, 5, 156, 187];
const CALLDATA_BYTES_LEN: usize =
    FUNCTION_SELECTOR_BYTES_LEN + ERC20_TO_ADDRESS_BYTES_LEN + ERC20_AMOUNT_BYTES_LEN;

#[derive(Clone, Debug)]
pub struct EthTransactionInput {
    pub transaction_index: u32,
    pub transaction_proofs: MPTInput,
}

#[derive(Clone, Debug)]
pub struct EthTransactionInputAssigned<F: Field> {
    pub transaction_index: AssignedValue<F>,
    pub transaction_proofs: MPTProof<F>,
}

impl EthTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTransactionInputAssigned<F> {
        let transaction_index = (F::from(self.transaction_index as u64)).try_into().unwrap();
        let transaction_index = ctx.load_witness(transaction_index);
        let transaction_proofs = self.transaction_proofs.assign(ctx);

        EthTransactionInputAssigned { transaction_index, transaction_proofs }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionInput {
    pub block: Block<H256>,
    pub block_number: u32,
    pub block_hash: H256,
    // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub transaction: EthTransactionInput,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionInputAssigned<F: Field> {
    pub block_header: Vec<u8>,
    pub transaction: EthTransactionInputAssigned<F>,
}

impl EthBlockTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthBlockTransactionInputAssigned<F> {
        let transaction = self.transaction.assign(ctx);
        EthBlockTransactionInputAssigned { block_header: self.block_header, transaction }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionCircuit {
    pub inputs: EthBlockTransactionInput,
    pub block_header_config: BlockHeaderConfig,
}

impl EthBlockTransactionCircuit {
    pub fn from_provider(provider: &Provider<Http>, constructor: TransactionConstructor) -> Self {
        let inputs = get_transaction_input(
            provider,
            constructor.block_number,
            constructor.transaction_index,
            constructor.transaction_index_bytes,
            constructor.transaction_rlp,
            constructor.merkle_proof,
            constructor.transaction_pf_max_depth,
        );
        let block_header_config = get_block_header_config(&constructor.network);
        Self { inputs, block_header_config }
    }

    pub fn instance<F: Field>(&self, ctx: &mut Context<F>) -> Vec<F> {
        let EthBlockTransactionInput { block_hash, .. } = &self.inputs;
        let mut instance = Vec::with_capacity(1);
        instance.extend(encode_h256_to_field::<F>(block_hash));
        instance
    }
}

impl EthPreCircuit for EthBlockTransactionCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();

        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let input = self.inputs.assign(ctx);
        let (witness, digest) = chip.parse_transaction_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            &self.block_header_config,
        );

        let EIP1186ResponseDigest { index, block_hash, transaction_is_empty, transaction_field } =
            digest;
        println!("chain_id:{:?}", transaction_field.chain_id);
        println!("hash:{:?}", transaction_field.hash);
        println!("from:{:?}", transaction_field.from);
        println!("to:{:?}", transaction_field.to);
        println!("token:{:?}", transaction_field.token);
        println!("amount:{:?}", transaction_field.amount);
        println!("nonce:{:?}", transaction_field.nonce);
        println!("time_stamp:{:?}", transaction_field.time_stamp);

        let assigned_instances = block_hash
            .into_iter()
            .chain(transaction_field.hash)
            .chain([
                index,
                transaction_field.chain_id,
                transaction_field.from,
                transaction_field.to,
                transaction_field.token,
                transaction_field.amount,
                transaction_field.nonce,
                transaction_field.time_stamp,
                transaction_field.dest_transfer_address,
                transaction_field.dest_transfer_token,
            ])
            .collect_vec();

        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            range.gate.assert_is_const(ctx, &transaction_is_empty, &Fr::zero());
        }

        EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<Fr>,
                  rlp: RlpChip<Fr>,
                  keccak_rlcs: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {
                // ======== SECOND PHASE ===========
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                let _trace = chip.parse_transaction_proof_from_block_phase1(builder, witness);
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct EthTransactionField<F: Field> {
    pub hash: AssignedH256<F>,
    pub chain_id: AssignedValue<F>,
    pub from: AssignedValue<F>,
    pub to: AssignedValue<F>, // ETH:is the to field of tx;Erc20:Erc20 to address
    pub token: AssignedValue<F>, // ETH:0x00...;Erc20:Erc20 token address (is the to field of tx)
    pub amount: AssignedValue<F>,
    pub nonce: AssignedValue<F>,
    pub time_stamp: AssignedValue<F>,
    pub dest_transfer_address: AssignedValue<F>, // Cross-address transfer is not currently supported.
    pub dest_transfer_token: AssignedValue<F>, // Cross-address transfer is not currently supported.
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub index: AssignedValue<F>,
    pub block_hash: AssignedH256<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub transaction_is_empty: AssignedValue<F>,
    pub transaction_field: EthTransactionField<F>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionTrace<F: Field> {
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub transaction_trace: EthTransactionTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionExtraWitness<F: Field> {
    pub hash: AssignedH256<F>,
    pub chain_id: AssignedValue<F>,
    pub from: AssignedValue<F>,
    pub to: AssignedValue<F>,
    pub token: AssignedValue<F>,
    pub amount: AssignedValue<F>,
    pub nonce: AssignedValue<F>,
    pub dest_transfer_address: AssignedValue<F>,
    pub dest_transfer_token: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionTraceWitness<F: Field> {
    transaction_witness: RlpArrayTraceWitness<F>,
    mpt_witness: MPTProofWitness<F>,
    extra_witness: EthTransactionExtraWitness<F>,
}

impl<F: Field> EthTransactionTraceWitness<F> {
    pub fn get_nonce(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[0]
    }
    pub fn get_gas_price(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[1]
    }
    pub fn get_gas_limit(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[2]
    }
    pub fn get_to(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[3]
    }
    pub fn get_value(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[4]
    }
    pub fn get_data(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[5]
    }
    pub fn get_v(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[6]
    }
    pub fn get_r(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[7]
    }
    pub fn get_s(&self) -> &RlpFieldWitness<F> {
        &self.transaction_witness.field_witness[8]
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub transaction_witness: EthTransactionTraceWitness<F>,
}

pub trait EthBlockTransactionChip<F: Field> {
    // ================= FIRST PHASE ================

    fn parse_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transaction_index: &AssignedValue<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTProof<F>,
    ) -> EthTransactionTraceWitness<F>;

    fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transaction_index: &AssignedValue<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTProof<F>,
    ) -> EthTransactionTraceWitness<F>;

    // ================= SECOND PHASE ================

    fn parse_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F>
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F>;

    fn parse_transaction_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F>;
}

impl<'chip, F: Field> EthBlockTransactionChip<F> for EthChip<'chip, F> {
    // ================= FIRST PHASE ================

    fn parse_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let transaction_index = input.transaction.transaction_index;

        let block_witness = {
            let ctx = thread_pool.main(FIRST_PHASE);
            let mut block_header = input.block_header;
            block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);
            self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config)
        };
        let ctx = thread_pool.main(FIRST_PHASE);
        let block_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        let transactions_root = &block_witness.get_transactions_root().field_cells;

        // timestamp
        let time_stamp =
            self.rlp_field_witnesses_to_uint(ctx, vec![&block_witness.get_timestamp()], vec![8])[0];

        // drop ctx
        let transaction_witness = self.parse_eip1186_proof_phase0(
            thread_pool,
            keccak,
            &transaction_index,
            transactions_root,
            input.transaction.transaction_proofs,
        );

        let digest = EIP1186ResponseDigest {
            index: transaction_index,
            block_hash: block_hash.try_into().unwrap(),
            transaction_is_empty: transaction_witness.mpt_witness.slot_is_empty,
            transaction_field: EthTransactionField {
                hash: transaction_witness.extra_witness.hash,
                chain_id: transaction_witness.extra_witness.chain_id,
                from: transaction_witness.extra_witness.from,
                to: transaction_witness.extra_witness.to,
                token: transaction_witness.extra_witness.token,
                amount: transaction_witness.extra_witness.amount,
                nonce: transaction_witness.extra_witness.nonce,
                time_stamp,
                dest_transfer_address: transaction_witness.extra_witness.dest_transfer_address,
                dest_transfer_token: transaction_witness.extra_witness.dest_transfer_token,
            },
        };
        (EthBlockTransactionTraceWitness { block_witness, transaction_witness }, digest)
    }

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transaction_index: &AssignedValue<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTProof<F>,
    ) -> EthTransactionTraceWitness<F> {
        let ctx = thread_pool.main(FIRST_PHASE);
        let transaction_trace = self.parse_transaction_proof_phase0(
            ctx,
            keccak,
            transaction_index,
            transactions_root,
            transaction_proofs,
        );
        transaction_trace
    }

    fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transaction_index: &AssignedValue<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTProof<F>,
    ) -> EthTransactionTraceWitness<F> {
        // ctx.constrain_equal(&transaction_proofs.key_bytes,transaction_index); key_bytes in transaction_proofs is constructed by transaction_index itself, which seems unnecessary to verify.

        // check MPT root is transactions_root
        for (pf_root, root) in
            transaction_proofs.root_hash_bytes.iter().zip(transactions_root.iter())
        {
            ctx.constrain_equal(pf_root, root);
        }

        let transaction_type = transaction_proofs.value_bytes.first().unwrap();

        let tx_type_critical_value = load_transaction_type(ctx, EIP_TX_TYPE_CRITICAL_VALUE);

        let zero = ctx.load_constant(F::from(0));
        let is_not_legacy_transaction =
            self.range().is_less_than(ctx, *transaction_type, tx_type_critical_value, NUM_BITS);

        let mut transaction_rlp_bytes = transaction_proofs.value_bytes.to_vec();
        let mut field_lens = EIP_2718_TX_TYPE_FIELDS_MAX_FIELDS_LEN.to_vec();
        let mut join_hash_len = zero;

        if is_not_legacy_transaction.value == zero.value {
            let legacy_transaction_type = load_transaction_type(ctx, EIP_2718_TX_TYPE);
            ctx.constrain_equal(transaction_type, &legacy_transaction_type);
        } else {
            transaction_rlp_bytes = transaction_rlp_bytes[1..].to_vec();
            field_lens = EIP_1559_TX_TYPE_FIELDS_MAX_FIELDS_LEN.to_vec();
            let one = ctx.load_constant(F::from(1));
            join_hash_len = one;
        }

        let transaction_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            transaction_rlp_bytes,
            &field_lens.as_slice(), //Maximum number of bytes per field. For example, the uint256 is 32 bytes.
            true,
        );

        // parse calldata Todo:Need to separate 2718 from 1559
        let mut calldata_witness;
        let mut tx_chain_id;
        let mut tx_token_address = zero; // Eth is 0x00;Erc20 is tx's to
        let mut tx_to_witness;
        let mut tx_amount_witness;
        let mut tx_nonce_witness;
        // let mock_calldata = Vec::from_hex("a9059cbb0000000000000000000000003620401ebbc40533218d2d0f2c01398dc9148b6f0000000000000000000000000000000000000000000000000000000000116520").unwrap();
        // let calldata = load_bytes(ctx, mock_calldata.as_slice());
        if is_not_legacy_transaction.value == zero.value {
            // [nonce,gasPrice,gasLimit,to,value,data,v,r,s]
            calldata_witness = &transaction_witness.field_witness[5];
            tx_to_witness = &transaction_witness.field_witness[3];
            tx_amount_witness = &transaction_witness.field_witness[4];
            tx_nonce_witness = &transaction_witness.field_witness[0];

            // Derive the original chain ID
            //         let numSub
            //         if ((v - 35) % 2 === 0) {
            //           numSub = 35
            //         } else {
            //           numSub = 36
            //         }
            //         // Use derived chain ID to create a proper Common
            //         chainIdBigInt = BigInt(v - numSub) / BigInt(2)
            let tx_v_witness = &transaction_witness.field_witness[6];
            let tx_v = self.rlp_field_witnesses_to_uint(ctx, vec![tx_v_witness], vec![32])[0];
            let thirty_five = ctx.load_constant(F::from(35));
            let thirty_six = ctx.load_constant(F::from(36));
            // v - 35
            let dividend = self.gate().sub(ctx, tx_v, thirty_five);
            // (v - 35) % 2
            let divisor = 2u64;
            let divisor_assigned = ctx.load_constant(F::from(divisor));
            let (quotient, remainder) = self.range().div_mod(ctx, dividend, divisor, 32);
            // (v - 35) % 2 === 0
            // Whether the result of multiplying the quotient by the divisor and adding the remainder is equal to the dividend
            let divisor_mul_quotient = self.gate().mul(ctx, divisor_assigned, quotient);
            let expect_dividend = self.gate().add(ctx, divisor_mul_quotient, remainder);
            let is_equal = self.gate().is_equal(ctx, dividend, expect_dividend);
            // num_sub = 36 - ( is_equal )
            let num_sub = self.gate().sub(ctx, thirty_six, is_equal);
            let tx_v_sub_num_sub = self.gate().sub(ctx, tx_v, num_sub);
            tx_chain_id = self.gate().div_unsafe(ctx, tx_v_sub_num_sub, divisor_assigned);
        } else {
            // [chainId,nonce,maxPriorityFeePerGas,maxFeePerGas,gasLimit,to,value,data,accessList,v,r,s]
            calldata_witness = &transaction_witness.field_witness[7];
            tx_to_witness = &transaction_witness.field_witness[5];
            tx_amount_witness = &transaction_witness.field_witness[6];
            tx_nonce_witness = &transaction_witness.field_witness[1];

            // tx source chain id
            tx_chain_id = self.rlp_field_witnesses_to_uint(
                ctx,
                vec![&transaction_witness.field_witness[0]],
                vec![32],
            )[0];
        }

        // tx to & tx amount
        let mut tx_to;
        let mut tx_amount;
        {
            let tx_fields = self.rlp_field_witnesses_to_uint(
                ctx,
                vec![&tx_to_witness, &tx_amount_witness],
                vec![32, 32],
            );
            tx_to = tx_fields[0];
            tx_amount = tx_fields[1];
        }

        let function_selector = load_bytes(ctx, &FUNCTION_SELECTOR_ERC20_TRANSFER);

        let mut new_calldata = Vec::with_capacity(CALLDATA_BYTES_LEN);
        let calldata_is_erc20_bytes_len = ctx.load_constant(F::from(CALLDATA_BYTES_LEN as u64));

        // Determine whether the length of the calldata meets the length required by ERC20
        if calldata_witness.field_len.value == calldata_is_erc20_bytes_len.value {
            let calldata = calldata_witness.field_cells[0..CALLDATA_BYTES_LEN - 1].to_vec();
            let mut is_function_selector = ctx.load_constant(F::from(1));

            for i in 0..CALLDATA_BYTES_LEN - 1 {
                let val_byte = self.gate().select(ctx, calldata[i + 1], calldata[i], zero);

                if i >= 0 && i <= FUNCTION_SELECTOR_BYTES_LEN - 1 {
                    let byte_is_equal =
                        self.gate().is_equal(ctx, calldata[i], function_selector[i]);
                    is_function_selector =
                        self.gate().mul(ctx, is_function_selector, byte_is_equal);
                }
                new_calldata.push(val_byte);
            }

            let val_byte = self.gate().select(ctx, zero, calldata[CALLDATA_BYTES_LEN - 1], zero);
            new_calldata.push(val_byte);

            // is erc20 transaction
            if is_function_selector.value != zero.value {
                let erc20_to_address_bytes = &new_calldata[FUNCTION_SELECTOR_BYTES_LEN
                    ..FUNCTION_SELECTOR_BYTES_LEN + ERC20_TO_ADDRESS_BYTES_LEN];
                let erc20_to_address_len = ctx.load_constant(
                    (F::from(erc20_to_address_bytes.len() as u64)).try_into().unwrap(),
                );
                let _erc20_to_address = bytes_be_var_to_fixed(
                    ctx,
                    self.gate(),
                    &erc20_to_address_bytes,
                    erc20_to_address_len,
                    32,
                );
                tx_token_address = tx_to;
                tx_to = bytes_be_to_uint(ctx, self.gate(), &_erc20_to_address, 32);

                let erc20_amount_bytes = &new_calldata
                    [FUNCTION_SELECTOR_BYTES_LEN + ERC20_TO_ADDRESS_BYTES_LEN..CALLDATA_BYTES_LEN];
                let erc20_amount_len = ctx
                    .load_constant((F::from(erc20_amount_bytes.len() as u64)).try_into().unwrap());
                let _erc20_amount = bytes_be_var_to_fixed(
                    ctx,
                    self.gate(),
                    &erc20_amount_bytes,
                    erc20_amount_len,
                    32,
                );
                tx_amount = bytes_be_to_uint(ctx, self.gate(), &_erc20_amount, 32);
            }
        }

        let real_join_hash_len = self.gate().add(ctx, transaction_witness.rlp_len, join_hash_len);

        let hash_idx = keccak.keccak_var_len(
            ctx,
            self.range(),
            transaction_proofs.value_bytes.to_vec(), // depends on the value of the constant TX_MAX_LEN = 789,
            None,
            real_join_hash_len,
            0,
        );

        let hash_bytes = keccak.var_len_queries[hash_idx].output_assigned.clone();
        let hash: [_; 2] = bytes_be_to_u128(ctx, self.gate(), &hash_bytes).try_into().unwrap();

        // tx from
        let tx_from = zero;

        // tx nonce
        let tx_nonce = self.rlp_field_witnesses_to_uint(ctx, vec![&tx_nonce_witness], vec![32])[0];

        // dest_transfer
        let dest_transfer_address = zero;
        let dest_transfer_token = zero;

        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_phase0(ctx, keccak, transaction_proofs);

        EthTransactionTraceWitness {
            transaction_witness,
            mpt_witness,
            extra_witness: EthTransactionExtraWitness {
                hash,
                chain_id: tx_chain_id,
                from: tx_from,
                to: tx_to,
                token: tx_token_address,
                amount: tx_amount,
                nonce: tx_nonce,
                dest_transfer_address,
                dest_transfer_token,
            },
        }
    }

    // ================= SECOND PHASE ================

    fn parse_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let block_trace =
            self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let transaction_trace =
            self.parse_eip1186_proof_phase1(thread_pool, witness.transaction_witness);
        EthBlockTransactionTrace { block_trace, transaction_trace }
    }

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let transaction_trace = self.parse_transaction_proof_phase1((ctx_gate, ctx_rlc), witness);

        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), 12);

        transaction_trace
    }

    fn parse_transaction_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F> {
        self.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        let value_trace = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.transaction_witness, true)
            .field_trace
            .try_into()
            .unwrap();
        EthTransactionTrace { value_trace }
    }
}
