use std::{cell::RefCell};
use std::collections::HashSet;
use ethers_core::abi::AbiEncode;

use ethers_core::types::{Block, Bytes, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::utils::bit_length;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use lazy_static::lazy_static;
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, EthPreCircuit, Network};
use crate::block_header::{BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness, get_block_header_config};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{MPTFixedKeyProof, MPTFixedKeyProofWitness, MPTUnFixedKeyInput};
use crate::providers::{ get_transaction_field_rlp, get_transaction_input};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{FIRST_PHASE, RlcContextPair, RlcTrace};
use crate::transaction::{EIP_1559_TX_TYPE_FIELDS_ITEM, EIP_1559_TX_TYPE_FIELDS_MAX_FIELDS_LEN, EIP_1559_TX_TYPE_FIELDS_NUM, EIP_2718_TX_TYPE, EIP_2718_TX_TYPE_FIELDS_ITEM, EIP_2718_TX_TYPE_FIELDS_MAX_FIELDS_LEN, EIP_2718_TX_TYPE_FIELDS_NUM, EIP_2718_TX_TYPE_INTERNAL, EIP_TX_TYPE_CRITICAL_VALUE, get_transaction_type, load_transaction_type, TX_INDEX_MAX_LEN};
use crate::util::helpers::{bytes_to_vec_u8, load_bytes};

pub mod tests;
pub mod helper;

// lazy_static! {
//     static ref KECCAK_RLP_EMPTY_STRING: Vec<u8> =
//         Vec::from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
// }

const NUM_BITS :usize = 8;

#[derive(Clone, Debug)]
pub struct EthTransactionInput {
    pub transaction_index: u32,
    pub transaction_proofs: MPTUnFixedKeyInput,
}

#[derive(Clone, Debug)]
pub struct EthTransactionInputAssigned<F: Field> {
    pub transaction_index: AssignedValue<F>,
    pub transaction_proofs: MPTFixedKeyProof<F>,
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
pub struct EthBlockTransactionCircuit{
    pub inputs: EthBlockTransactionInput,
    pub block_header_config: BlockHeaderConfig,
}

impl EthBlockTransactionCircuit {
    pub fn from_provider(
        provider: &Provider<Http>,
        block_number: u32,
        transaction_index: u32,
        transaction_rlp: Vec<u8>,
        merkle_proof: Vec<Bytes>,
        transaction_pf_max_depth: usize,
        network: Network,
    ) -> Self {
        let inputs = get_transaction_input(
            provider,
            block_number,
            transaction_index,
            transaction_rlp,
            merkle_proof,
            transaction_pf_max_depth,
        );
        let block_header_config = get_block_header_config(&network);
        Self { inputs, block_header_config }
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
            &self.block_header_config);

        let EIP1186ResponseDigest {
            index,
            slots_values,
            transaction_is_empty
        } = digest;

        let assigned_instances = vec![index].into_iter()
            .chain(
                slots_values
            )
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
pub struct EIP1186ResponseDigest<F: Field> {
    pub index: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<AssignedValue<F>>,
    pub transaction_is_empty: AssignedValue<F>,
}


#[derive(Clone, Debug)]
pub struct EthTransactionTrace<F: Field> {
    pub value_trace:Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub transaction_trace: EthTransactionTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionTraceWitness<F: Field> {
    array_witness: RlpArrayTraceWitness<F>,
    mpt_witness: MPTFixedKeyProofWitness<F>,
}

impl<F: Field> EthTransactionTraceWitness<F> {
    pub fn get_nonce(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[0]
    }
    pub fn get_gas_price(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[1]
    }
    pub fn get_gas_limit(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[2]
    }
    pub fn get_to(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[3]
    }
    pub fn get_value(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[4]
    }
    pub fn get_data(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[5]
    }
    pub fn get_v(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[6]
    }
    pub fn get_r(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[7]
    }
    pub fn get_s(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[8]
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
        transaction_proofs: MPTFixedKeyProof<F>,
    ) -> EthTransactionTraceWitness<F>;

    fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transaction_index: &AssignedValue<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTFixedKeyProof<F>,
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
            Self: EthBlockHeaderChip<F>, {

        let transaction_index = input.transaction.transaction_index;

        let block_witness = {
            let ctx = thread_pool.main(FIRST_PHASE);
            let mut block_header = input.block_header;
            block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);
            self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config)
        };
        let transactions_root = &block_witness.get_transactions_root().field_cells;

        // drop ctx
        let transaction_witness = self.parse_eip1186_proof_phase0(
            thread_pool,
            keccak,
            &transaction_index,
            transactions_root,
            input.transaction.transaction_proofs,
        );
        let transaction_rlp = transaction_witness.mpt_witness.value_bytes.to_vec();

        let digest = EIP1186ResponseDigest {
            index: transaction_index,
            slots_values: transaction_rlp,
            transaction_is_empty: transaction_witness.mpt_witness.slot_is_empty,
        };
        (EthBlockTransactionTraceWitness { block_witness, transaction_witness }, digest)
    }

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transaction_index: &AssignedValue<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTFixedKeyProof<F>,
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

    fn parse_transaction_proof_phase0(&self, ctx: &mut Context<F>, keccak: &mut KeccakChip<F>, transaction_index: &AssignedValue<F>,transactions_root: &[AssignedValue<F>], transaction_proofs: MPTFixedKeyProof<F>) -> EthTransactionTraceWitness<F> {

        // ctx.constrain_equal(&transaction_proofs.key_bytes,transaction_index);

        // check MPT root is transactions_root
        for (pf_root, root) in transaction_proofs.root_hash_bytes.iter().zip(transactions_root.iter()) {
            ctx.constrain_equal(pf_root, root);
        }


        let transaction_type = transaction_proofs.value_bytes.first().unwrap();

        let tx_type_critical_value = load_transaction_type(ctx,EIP_TX_TYPE_CRITICAL_VALUE);

        let zero = ctx.load_constant(F::from(0));
        let is_not_legacy_transaction =
            self.range().is_less_than(ctx, *transaction_type, tx_type_critical_value, NUM_BITS);

        let mut transaction_rlp_bytes= transaction_proofs.value_bytes.to_vec();
        let mut field_lens = EIP_2718_TX_TYPE_FIELDS_MAX_FIELDS_LEN.to_vec();

        if is_not_legacy_transaction.value == zero.value{
            let legacy_transaction_type = load_transaction_type(ctx,EIP_2718_TX_TYPE);
            ctx.constrain_equal(transaction_type,&legacy_transaction_type);
        }else{
            transaction_rlp_bytes = transaction_proofs.value_bytes[1..].to_vec();
            field_lens = EIP_1559_TX_TYPE_FIELDS_MAX_FIELDS_LEN.to_vec();
        }

        println!("is_not_legacy_transaction:{:?}",&is_not_legacy_transaction.value);

        // let test_value = self.gate().select(
        //     ctx,
        //     transaction_proofs.value_bytes[3],
        //     transaction_proofs.value_bytes[2],
        //     type_is_not_zero
        // );//type_is_not_zero == 1 , value is a;type_is_not_zero == 0 , value is b

        // let one_nine_three = ctx.load_constant(F::from(193));
        // let zero = ctx.load_constant(F::from(0));
        // let c  = self.gate().mul_add(ctx,one_nine_three,zero,transaction_proofs.value_bytes[0]);
        // println!("c:{:?}",&c.value);

        println!("len:{:?}",&transaction_rlp_bytes.len());


        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            transaction_rlp_bytes,
            &field_lens.as_slice(),//Maximum number of bytes per field. For example, the uint256 is 32 bytes.
            true,
        );

        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, transaction_proofs);
        EthTransactionTraceWitness { array_witness, mpt_witness }
    }


    // ================= SECOND PHASE ================

    fn parse_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F>
        where
            Self: EthBlockHeaderChip<F> {
        let block_trace = self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let transaction_trace = self.parse_eip1186_proof_phase1(thread_pool, witness.transaction_witness);
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
        self.parse_mpt_inclusion_fixed_key_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        let value_trace = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.array_witness, true)
            .field_trace
            .try_into()
            .unwrap();
        EthTransactionTrace {
            value_trace
        }
    }
}







