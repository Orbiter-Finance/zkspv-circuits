mod tests;
pub mod util;

use std::cell::RefCell;

use ethers_core::types::{Block, Bytes, H256};
use ethers_providers::{Http, Provider, RetryClient};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::bit_length;
use halo2_base::{AssignedValue, Context};
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::block_header::{
    get_block_header_config, BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace,
    EthBlockHeaderTraceWitness,
};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{MPTInput, MPTProof, MPTProofWitness};
use crate::providers::get_receipt_input;
use crate::receipt::util::ReceiptConstructor;
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{RlcContextPair, FIRST_PHASE};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness};
use crate::transaction::{load_transaction_type, EIP_2718_TX_TYPE, EIP_TX_TYPE_CRITICAL_VALUE};
use crate::util::{bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, AssignedH256};
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, Network, ETH_LOOKUP_BITS};

const RECEIPT_FIELDS_NUM: usize = 4;
const RECEIPT_LOGS_BLOOM_MAX_LEN: usize = 256;

const RECEIPT_DATA_MAX_BYTES: usize = 128;
const RECEIPT_LOG_MAX_NUM: usize = 15;
const RECEIPT_TOPIC_MAX_NUM: usize = 4;
const RECEIPT_LOG_MAX_LEN: usize =
    3 + 21 + 3 + 33 * RECEIPT_TOPIC_MAX_NUM + 3 + RECEIPT_DATA_MAX_BYTES + 1;
const RECEIPT_FIELDS_MAX_FIELDS_LEN: [usize; RECEIPT_FIELDS_NUM] =
    [32 + 1, 32 + 1, RECEIPT_LOGS_BLOOM_MAX_LEN + 3, RECEIPT_LOG_MAX_NUM * RECEIPT_LOG_MAX_LEN];
pub(crate) const RECEIPT_MAX_LEN: usize =
    3 + 33 * 2 + RECEIPT_LOGS_BLOOM_MAX_LEN + 3 + RECEIPT_LOG_MAX_NUM * RECEIPT_LOG_MAX_LEN;
pub const TX_STATUS_SUCCESS: u8 = 1;
const NUM_BITS: usize = 8;

#[derive(Clone, Debug)]
pub struct EthReceiptInput {
    pub receipt_index: u64,
    pub receipt_proofs: MPTInput,
}

#[derive(Clone, Debug)]
pub struct EthReceiptInputAssigned<F: Field> {
    pub receipt_index: AssignedValue<F>,
    pub receipt_proofs: MPTProof<F>,
}

impl EthReceiptInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthReceiptInputAssigned<F> {
        let receipt_index = ctx.load_witness(F::from(self.receipt_index));
        let receipt_proofs = self.receipt_proofs.assign(ctx);

        EthReceiptInputAssigned { receipt_index, receipt_proofs }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptInput {
    pub block: Block<H256>,
    pub block_number: u64,
    pub block_hash: H256,
    // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub receipt: EthReceiptInput,
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptInputAssigned<F: Field> {
    pub block_header: Vec<u8>,
    pub receipt: EthReceiptInputAssigned<F>,
}

impl EthBlockReceiptInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthBlockReceiptInputAssigned<F> {
        let receipt = self.receipt.assign(ctx);
        EthBlockReceiptInputAssigned { block_header: self.block_header, receipt }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptCircuit {
    pub inputs: EthBlockReceiptInput,
    pub block_header_config: BlockHeaderConfig,
}

impl EthBlockReceiptCircuit {
    pub fn from_provider(
        provider: &Provider<RetryClient<Http>>,
        constructor: ReceiptConstructor,
    ) -> Self {
        let inputs = get_receipt_input(
            provider,
            constructor.transaction_hash,
            constructor.receipt_index_bytes,
            constructor.receipt_rlp,
            constructor.merkle_proof,
            constructor.receipt_pf_max_depth,
        );
        let block_header_config = get_block_header_config(&constructor.network);
        Self { inputs, block_header_config }
    }
}

impl EthPreCircuit for EthBlockReceiptCircuit {
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
        let (witness, digest) = chip.parse_receipt_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            &self.block_header_config,
        );

        let EIP1186ResponseDigest { block_hash, block_number, index, receipt_is_empty } = digest;

        let assigned_instances = block_hash.into_iter().chain([index]).collect_vec();
        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            range.gate.assert_is_const(ctx, &receipt_is_empty, &Fr::zero());
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
                let _trace = chip.parse_receipt_proof_from_block_phase1(builder, witness);
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub index: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    // pub slots_values: Vec<AssignedValue<F>>,
    pub receipt_is_empty: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptTrace<F: Field> {
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub receipt_trace: EthReceiptTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptTraceWitness<F: Field> {
    receipt_witness: RlpArrayTraceWitness<F>,
    mpt_witness: MPTProofWitness<F>,
}

impl<F: Field> EthReceiptTraceWitness<F> {
    pub fn get_status(&self) -> &RlpFieldWitness<F> {
        &self.receipt_witness.field_witness[0]
    }
    pub fn get_cumulative_gas_used(&self) -> &RlpFieldWitness<F> {
        &self.receipt_witness.field_witness[1]
    }
    pub fn get_logs_bloom(&self) -> &RlpFieldWitness<F> {
        &self.receipt_witness.field_witness[2]
    }
    // pub fn get_logs(&self) -> &RlpFieldWitness<F> {
    //     &self.array_witness.field_witness[3]
    // }
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub receipt_witness: EthReceiptTraceWitness<F>,
}

pub trait EthBlockReceiptChip<F: Field> {
    // ================= FIRST PHASE ================

    fn parse_receipt_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockReceiptInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockReceiptTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        receipts_root: &[AssignedValue<F>],
        receipt_proofs: MPTProof<F>,
    ) -> EthReceiptTraceWitness<F>;

    fn parse_receipt_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        receipts_root: &[AssignedValue<F>],
        receipt_proofs: MPTProof<F>,
    ) -> EthReceiptTraceWitness<F>;

    // ================= SECOND PHASE ================

    fn parse_receipt_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockReceiptTraceWitness<F>,
    ) -> EthBlockReceiptTrace<F>
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthReceiptTraceWitness<F>,
    ) -> EthReceiptTrace<F>;

    fn parse_receipt_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthReceiptTraceWitness<F>,
    ) -> EthReceiptTrace<F>;
}

impl<'chip, F: Field> EthBlockReceiptChip<F> for EthChip<'chip, F> {
    // ================= FIRST PHASE ================

    fn parse_receipt_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockReceiptInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockReceiptTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let ctx = thread_pool.main(FIRST_PHASE);
        let receipt_index = input.receipt.receipt_index;
        let mut block_header = input.block_header;
        block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);

        let block_witness =
            self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config);
        let receipts_root = &block_witness.get_receipts_root().field_cells;
        let block_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.get_number().field_cells;
        let block_num_len = block_witness.get_number().field_len;
        let block_number = bytes_be_var_to_fixed(
            ctx,
            self.gate(),
            block_num_bytes,
            block_num_len,
            block_header_config.block_number_max_bytes,
        );
        let block_number = bytes_be_to_uint(
            ctx,
            self.gate(),
            &block_number,
            block_header_config.block_number_max_bytes,
        );

        // drop ctx
        let receipt_witness = self.parse_eip1186_proof_phase0(
            thread_pool,
            keccak,
            receipts_root,
            input.receipt.receipt_proofs,
        );

        let digest = EIP1186ResponseDigest {
            block_hash: block_hash.try_into().unwrap(),
            block_number,
            index: receipt_index,
            receipt_is_empty: receipt_witness.mpt_witness.slot_is_empty,
        };
        (EthBlockReceiptTraceWitness { block_witness, receipt_witness }, digest)
    }

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        receipts_root: &[AssignedValue<F>],
        receipt_proofs: MPTProof<F>,
    ) -> EthReceiptTraceWitness<F> {
        let ctx = thread_pool.main(FIRST_PHASE);
        let receipt_trace =
            self.parse_receipt_proof_phase0(ctx, keccak, receipts_root, receipt_proofs);
        receipt_trace
    }

    fn parse_receipt_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        receipts_root: &[AssignedValue<F>],
        receipt_proofs: MPTProof<F>,
    ) -> EthReceiptTraceWitness<F> {
        // check MPT root is receipts_root
        for (mpt_root, re_root) in receipt_proofs.root_hash_bytes.iter().zip(receipts_root.iter()) {
            ctx.constrain_equal(mpt_root, re_root);
        }

        let transaction_type = receipt_proofs.value_bytes.first().unwrap();

        let tx_type_critical_value = load_transaction_type(ctx, EIP_TX_TYPE_CRITICAL_VALUE);

        let zero = ctx.load_constant(F::from(0));
        let is_not_legacy_transaction =
            self.range().is_less_than(ctx, *transaction_type, tx_type_critical_value, NUM_BITS);

        let mut receipt_rlp_bytes = receipt_proofs.value_bytes.to_vec();

        if is_not_legacy_transaction.value == zero.value {
            let legacy_transaction_type = load_transaction_type(ctx, EIP_2718_TX_TYPE);
            ctx.constrain_equal(transaction_type, &legacy_transaction_type);
        } else {
            receipt_rlp_bytes = receipt_rlp_bytes[1..].to_vec();
        }

        let receipt_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            receipt_rlp_bytes,
            &RECEIPT_FIELDS_MAX_FIELDS_LEN,
            true,
        );

        let tx_status_success = (F::from(TX_STATUS_SUCCESS as u64)).try_into().unwrap();
        let tx_status_success = ctx.load_witness(tx_status_success);

        // check tx_status is TX_STATUS_SUCCESS
        for (tx_status, success_status) in
            receipt_witness.field_witness[0].field_cells.iter().zip(vec![tx_status_success].iter())
        {
            ctx.constrain_equal(tx_status, success_status);
        }

        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_phase0(ctx, keccak, receipt_proofs);

        EthReceiptTraceWitness { receipt_witness, mpt_witness }
    }

    // ================= SECOND PHASE ================

    fn parse_receipt_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockReceiptTraceWitness<F>,
    ) -> EthBlockReceiptTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let block_trace =
            self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let receipt_trace = self.parse_eip1186_proof_phase1(thread_pool, witness.receipt_witness);
        EthBlockReceiptTrace { block_trace, receipt_trace }
    }

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthReceiptTraceWitness<F>,
    ) -> EthReceiptTrace<F> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let receipt_trace = self.parse_receipt_proof_phase1((ctx_gate, ctx_rlc), witness);

        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), 12);

        receipt_trace
    }

    fn parse_receipt_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthReceiptTraceWitness<F>,
    ) -> EthReceiptTrace<F> {
        self.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);

        let value_trace = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.receipt_witness, true)
            .field_trace
            .try_into()
            .unwrap();

        EthReceiptTrace { value_trace }
    }
}
