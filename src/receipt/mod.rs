use std::{cell::RefCell, env::var};
use std::ops::Index;
use ethers_core::k256::sha2::digest::typenum::private::IsEqualPrivate;

use ethers_core::types::{Block, Bytes, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::utils::bit_length;
use itertools::{equal, Itertools};
use rlp::Rlp;
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, Network};
use crate::block_header::{EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness, GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES};
use crate::keccak::{FixedLenRLCs, FnSynthesize, get_bytes, KeccakChip, VarLenRLCs};
use crate::mpt::{AssignedBytes, MPTFixedKeyProof, MPTFixedKeyProofWitness, MPTUnFixedKeyInput};
use crate::r#type::{EIP_1559_PREFIX, EIP_2718_PREFIX, EIP_2930_PREFIX, TX_STATUS_SUCCESS};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldWitness};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{FIRST_PHASE, RlcContextPair, RlcTrace};
use crate::util::{AssignedH256, bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, decode_field_to_u256, EthConfigParams};

mod tests;

#[derive(Clone, Debug)]
pub struct EthReceiptInput {
    pub receipt_index: u32,
    pub receipt_proofs: MPTUnFixedKeyInput, // key proof
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
    pub network: Network,
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
        use crate::providers::get_block_storage_input_receipt;

        let inputs = get_block_storage_input_receipt(
            provider,
            block_number,
            receipt_index,
            receipt_rlp,
            merkle_proof,
            receipt_pf_max_depth,
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
        let (witness, digest) = chip.parse_receipt_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input, self.network);

        let EIP1186ResponseDigest {
            block_hash,
            block_number,
            index,
            slots_values,
            receipt_is_empty
        } = digest;

        let assigned_instances = block_hash
            .into_iter()
            .chain([block_number, index])
            .chain(
                slots_values
            )
            .collect_vec();
        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            range.gate.assert_is_const(ctx, &receipt_is_empty, &F::zero());
        }

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
                let _trace = chip.parse_receipt_proof_from_block_phase1(builder, witness);
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
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub index: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<AssignedValue<F>>,
    pub receipt_is_empty: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EthReceiptTrace<F: Field> {
    pub status_trace: RlcTrace<F>,
    pub cumulative_gas_used_trace: RlcTrace<F>,
    // pub logs_bloom_trace: RlcTrace<F>,
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
    pub fn get(&self, receipt_field: &str) -> &RlpFieldWitness<F> {
        match receipt_field {
            "status" => &self.array_witness.field_witness[0],
            "cumulativeGasUsed" => &self.array_witness.field_witness[1],
            // "logsBloom" => &self.array_witness.field_witness[2],
            // "logs" => &self.array_witness.field_witness[3],
            _ => panic!("invalid receipt field"),
        }
    }
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
        network: Network,
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
        network: Network,
    ) -> (EthBlockReceiptTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>, {
        let ctx = thread_pool.main(FIRST_PHASE);
        let receipt_index = input.receipt.receipt_index;
        let mut block_header = input.block_header;
        let max_len = match network {
            Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
        };
        block_header.resize(max_len, 0);
        let block_witness = self.decompose_block_header_phase0(ctx, keccak, &block_header, network);
        let receipts_root = &block_witness.get("receipts_root").field_cells;
        let block_hash_hi_lo = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.get("number").field_cells;
        let block_num_len = block_witness.get("number").field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 4);
        let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, 4);

        // drop ctx
        let receipt_witness = self.parse_eip1186_proof_phase0(
            thread_pool,
            keccak,
            receipts_root,
            input.receipt.receipt_proofs,
        );
        let receipt_rlp = receipt_witness.mpt_witness.value_bytes.to_vec();

        let digest = EIP1186ResponseDigest {
            block_hash: block_hash_hi_lo.try_into().unwrap(),
            block_number,
            index: receipt_index,
            slots_values: receipt_rlp,
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

        let bytes_to_vec_u8 = |rlp_value: &AssignedBytes<F>, input_bytes: Option<Vec<u8>>| {
            input_bytes.unwrap_or_else(|| get_bytes(&rlp_value[..]))
        };
        let value_u8 = bytes_to_vec_u8(&receipt_proofs.value_bytes, None);
        let value_prefix = value_u8[0];
        let mut rlp_value: AssignedBytes<F> = vec![];

        // let nested_array = |rlp_value: &AssignedBytes<F>, index: usize| {
        //     let a =vec![*rlp_value.get(index).unwrap()] ;
        //     let rlp_u8 = bytes_to_vec_u8(&a, None);
        // };

        if value_prefix == EIP_1559_PREFIX || value_prefix == EIP_2930_PREFIX {
            if let Some((_, elements)) = receipt_proofs.value_bytes.split_first() {
                rlp_value = elements.to_vec();
            }
        }


        // nested_array(&rlp_value, rlp_value.len()-1);


        // parse [status,cumulativeGasUsed]; Todo: The logsBloom,logs field will not be parsed for the time being.
        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            rlp_value,
            &[8, 8],//Maximum number of bytes per field. For example, the uint64 is 8 bytes.
            false,
        );

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

        let array_trace: [_; 2] = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.array_witness, false)
            .field_trace
            .try_into()
            .unwrap();

        let [
        status_trace,
        cumulative_gas_used_trace,
        // logs_bloom_trace,
        // logs_trace,
        ] = array_trace.map(|trace| trace.field_trace);

        EthReceiptTrace {
            status_trace,
            cumulative_gas_used_trace,
            // logs_bloom_trace,
            // logs_trace,
        }
    }
}