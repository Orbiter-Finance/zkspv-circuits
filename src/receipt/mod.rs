mod tests;

use std::{cell::RefCell};

use ethers_core::types::{Block, Bytes, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::utils::bit_length;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, EthPreCircuit, Network};
use crate::block_header::{BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness, get_block_header_config};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{AssignedBytes, MPTFixedKeyProof, MPTFixedKeyProofWitness, MPTUnFixedKeyInput};
use crate::providers::{get_receipt_field_rlp, get_receipt_input};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldWitness};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{FIRST_PHASE, RlcContextPair, RlcTrace};
use crate::transaction::get_transaction_type;
use crate::util::{AssignedH256, bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed};
use crate::util::helpers::{bytes_to_vec_u8};

// Status of the transaction
pub const TX_STATUS_SUCCESS: u8 = 1;

pub const TX_RECEIPT_FIELD: [u8; 3] = [0, 1, 2];

#[derive(Clone, Debug)]
pub struct EthReceiptInput {
    pub receipt_index: u32,
    pub receipt_proofs: MPTUnFixedKeyInput,
}

#[derive(Clone, Debug)]
pub struct EthReceiptInputAssigned<F: Field> {
    pub receipt_index: AssignedValue<F>,
    pub receipt_proofs: MPTFixedKeyProof<F>,
}

impl EthReceiptInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthReceiptInputAssigned<F> {
        let receipt_index = (F::from(self.receipt_index as u64)).try_into().unwrap();
        let receipt_index = ctx.load_witness(receipt_index);
        let receipt_proofs = self.receipt_proofs.assign(ctx);

        EthReceiptInputAssigned { receipt_index, receipt_proofs }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptInput {
    pub block: Block<H256>,
    pub block_number: u32,
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
        provider: &Provider<Http>,
        block_number: u32,
        receipt_index: u32,
        receipt_rlp: Vec<u8>,
        merkle_proof: Vec<Bytes>,
        receipt_pf_max_depth: usize,
        network: Network,
    ) -> Self {
        let inputs = get_receipt_input(
            provider,
            block_number,
            receipt_index,
            receipt_rlp,
            merkle_proof,
            receipt_pf_max_depth,
        );
        let block_header_config = get_block_header_config(&network);
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
            &self.block_header_config);

        let EIP1186ResponseDigest {
            block_hash,
            block_number,
            index,
            // slots_values,
            receipt_is_empty
        } = digest;

        let assigned_instances = block_hash
            .into_iter()
            .chain([block_number, index])
            // .chain(
            //     slots_values
            // )
            .collect_vec();
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
    pub status_trace: RlcTrace<F>,
    pub cumulative_gas_used_trace: RlcTrace<F>,
    pub logs_bloom_trace: RlcTrace<F>,
    // pub logs_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockReceiptTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub receipt_trace: EthReceiptTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptTraceWitness<F: Field> {
    array_witness: RlpArrayTraceWitness<F>,
    mpt_witness: MPTFixedKeyProofWitness<F>,
}

impl<F: Field> EthReceiptTraceWitness<F> {
    pub fn get_status(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[0]
    }
    pub fn get_cumulative_gas_used(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[1]
    }
    pub fn get_logs_bloom(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[2]
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
        receipt_proofs: MPTFixedKeyProof<F>,
    ) -> EthReceiptTraceWitness<F>;

    fn parse_receipt_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        receipts_root: &[AssignedValue<F>],
        receipt_proofs: MPTFixedKeyProof<F>,
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
            Self: EthBlockHeaderChip<F>, {
        let ctx = thread_pool.main(FIRST_PHASE);
        let receipt_index = input.receipt.receipt_index;
        let mut block_header = input.block_header;
        block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);

        let block_witness = self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config);
        let receipts_root = &block_witness.get_parent_hash().field_cells;
        let block_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.get_number().field_cells;
        let block_num_len = block_witness.get_number().field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, block_header_config.block_number_max_bytes);
        let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, block_header_config.block_number_max_bytes);

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
            // slots_values: receipt_rlp,
            receipt_is_empty: receipt_witness.mpt_witness.slot_is_empty,
        };
        (EthBlockReceiptTraceWitness { block_witness, receipt_witness }, digest)
    }

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        receipts_root: &[AssignedValue<F>],
        receipt_proofs: MPTFixedKeyProof<F>,
    ) -> EthReceiptTraceWitness<F> {
        let ctx = thread_pool.main(FIRST_PHASE);
        let receipt_trace = self.parse_receipt_proof_phase0(
            ctx,
            keccak,
            receipts_root,
            receipt_proofs,
        );
        receipt_trace
    }

    fn parse_receipt_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        receipts_root: &[AssignedValue<F>],
        receipt_proofs: MPTFixedKeyProof<F>,
    ) -> EthReceiptTraceWitness<F> {

        // check MPT root is receipts_root
        for (mpt_root, re_root) in receipt_proofs.root_hash_bytes.iter().zip(receipts_root.iter()) {
            ctx.constrain_equal(mpt_root, re_root);
        }

        let mut non_prefix_bytes: AssignedBytes<F> = vec![];

        // Load a prefix and determine if it belongs to a specific prefix
        let receipt_value_prefix = &receipt_proofs.value_bytes.first().unwrap();
        let transaction_type = get_transaction_type(ctx, receipt_value_prefix);
        if transaction_type != 0 {
            // Todo: Identify nested lists
            non_prefix_bytes = receipt_proofs.value_bytes[1..].to_vec();
        }

        let non_prefix_bytes_u8 = bytes_to_vec_u8(&non_prefix_bytes);

        // Generate rlp encoding for specific fields and generate a witness
        let dest_value_bytes = get_receipt_field_rlp(&non_prefix_bytes_u8, 4, TX_RECEIPT_FIELD);
        let mut load_bytes =
            |bytes: &[u8]| ctx.assign_witnesses(bytes.iter().map(|x| F::from(*x as u64)));
        let receipt_rlp_bytes = load_bytes(&dest_value_bytes);


        // parse [status,cumulativeGasUsed,logsBloom]
        // Todo: The logs field will not be parsed for the time being.
        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            receipt_rlp_bytes,
            &[8, 8, 256],//Maximum number of bytes per field. For example, the uint64 is 8 bytes.
            false,
        );


        // minus the length of the removed prefix
        // array_witness.rlp_len = self.gate().sub(ctx,array_witness.rlp_len,Constant(F::one()));

        let tx_status_success = (F::from(TX_STATUS_SUCCESS as u64)).try_into().unwrap();
        let tx_status_success = ctx.load_witness(tx_status_success);

        // check tx_status is TX_STATUS_SUCCESS
        for (tx_status, success_status) in array_witness.field_witness[0].field_cells.iter().zip(vec![tx_status_success].iter()) {
            ctx.constrain_equal(tx_status, success_status);
        }

        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, receipt_proofs);

        EthReceiptTraceWitness {
            array_witness,
            mpt_witness,
        }
    }


    // ================= SECOND PHASE ================

    fn parse_receipt_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockReceiptTraceWitness<F>,
    ) -> EthBlockReceiptTrace<F>
        where
            Self: EthBlockHeaderChip<F> {
        let block_trace = self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let receipt_trace = self.parse_eip1186_proof_phase1(thread_pool, witness.receipt_witness);
        EthBlockReceiptTrace { block_trace, receipt_trace }
    }

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthReceiptTraceWitness<F>,
    ) -> EthReceiptTrace<F> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let copy_witness = &witness.clone();
        let receipt_trace = self.parse_receipt_proof_phase1((ctx_gate, ctx_rlc), witness);

        let max_len = (2 * &copy_witness.mpt_witness.key_byte_len).max(copy_witness.array_witness.rlp_array.len());
        let cache_bits = bit_length(max_len as u64);
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), cache_bits);

        receipt_trace
    }

    fn parse_receipt_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthReceiptTraceWitness<F>,
    ) -> EthReceiptTrace<F> {
        self.parse_mpt_inclusion_fixed_key_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);

        let array_trace: [_; 3] = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.array_witness, false)
            .field_trace
            .try_into()
            .unwrap();

        let [
        status_trace,
        cumulative_gas_used_trace,
        logs_bloom_trace,
        // logs_trace,
        ] = array_trace.map(|trace| trace.field_trace);


        EthReceiptTrace {
            status_trace,
            cumulative_gas_used_trace,
            logs_bloom_trace,
            // logs_trace,
        }
    }
}