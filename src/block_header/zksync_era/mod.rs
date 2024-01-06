mod tests;

use crate::keccak::{
    parallelize_keccak_phase0, FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs,
};
use crate::mpt::AssignedBytes;
use crate::providers::get_zksync_era_block_with_txs_input;
use crate::rlp::builder::{parallelize_phase1, RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{RlcContextPair, RlcFixedTrace, RlcTrace, FIRST_PHASE};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness};
use crate::util::helpers::load_bytes;
use crate::util::{
    bytes_be_to_u128, bytes_be_var_to_fixed, get_hash_bytes_inner_product, is_zero_vec,
};
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, Network, ETH_LOOKUP_BITS};
use ethers_core::types::H256;
use ethers_providers::{Http, Provider, RetryClient};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::bit_length;
use halo2_base::{AssignedValue, Context};
use itertools::Itertools;
use std::cell::RefCell;
use std::iter::repeat;
use zkevm_keccak::util::eth_types::Field;
const NUM_BLOCK_HEADER_FIELDS: usize = 3;
const BLOCK_HEADER_MAX_FIELD_LENS: [usize; NUM_BLOCK_HEADER_FIELDS] = [4, 8, 32];
pub(crate) const BLOCK_HEADER_RLP_MAX_BYTES: usize = 5 + 9 + 33;
pub(crate) const BLOCK_INCLUDE_TXS_MAX_NUMBER: u64 = 350;

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockHeaderInput {
    pub block_header: Vec<u8>,
    pub txs_hash: Vec<H256>,
    pub max_txs_len: u64,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockHeaderInputAssigned<F: Field> {
    pub block_header: AssignedBytes<F>,
    pub txs_hash: Vec<AssignedBytes<F>>,
    pub max_txs_len: AssignedValue<F>,
}

impl ZkSyncEraBlockHeaderInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ZkSyncEraBlockHeaderInputAssigned<F> {
        let mut block_header = self.block_header;
        block_header.resize(BLOCK_HEADER_RLP_MAX_BYTES, 0u8);
        let block_header = load_bytes(ctx, block_header.as_slice());
        let mut txs_hash =
            self.txs_hash.iter().map(|tx| load_bytes(ctx, tx.as_bytes())).collect_vec();
        for _ in 0..self.max_txs_len as usize - self.txs_hash.len() {
            txs_hash.push(load_bytes(ctx, H256::zero().as_bytes()));
        }
        assert_eq!(txs_hash.len() as u64, self.max_txs_len);
        let max_txs_len = ctx.load_witness(F::from(self.max_txs_len));

        ZkSyncEraBlockHeaderInputAssigned { block_header, txs_hash, max_txs_len }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockHeadersInput {
    pub headers: Vec<ZkSyncEraBlockHeaderInput>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockHeadersInputAssigned<F: Field> {
    pub headers: Vec<ZkSyncEraBlockHeaderInputAssigned<F>>,
}

impl ZkSyncEraBlockHeadersInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ZkSyncEraBlockHeadersInputAssigned<F> {
        let headers = self.headers.into_iter().map(|block| block.assign(ctx)).collect();
        ZkSyncEraBlockHeadersInputAssigned { headers }
    }
}

#[derive(Clone, Debug)]
/// The input datum for the block header chain circuit. It is used to generate a circuit.
pub struct ZkSyncEraBlockHeaderChainCircuit {
    inputs: ZkSyncEraBlockHeadersInput,
}

impl ZkSyncEraBlockHeaderChainCircuit {
    #[cfg(feature = "providers")]
    pub fn from_provider(
        provider: &Provider<RetryClient<Http>>,
        _network: Network,
        blocks_number: Vec<u64>,
    ) -> Self {
        let inputs = get_zksync_era_block_with_txs_input(provider, blocks_number);
        Self { inputs }
    }
}

impl EthPreCircuit for ZkSyncEraBlockHeaderChainCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();

        let ctx = builder.gate_builder.main(FIRST_PHASE);
        // ==== Load RLP encoding and decode ====
        let input = self.inputs.assign(ctx);
        let block_chain_witness =
            chip.decompose_block_headers_phase0(&mut builder.gate_builder, &mut keccak, input);

        EthCircuitBuilder::new(
            vec![],
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<Fr>,
                  rlp: RlpChip<Fr>,
                  keccak_rlcs: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {
                // ======== SECOND PHASE ===========
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                let _block_chain_trace =
                    chip.decompose_block_headers_phase1(builder, block_chain_witness);
            },
        )
    }
}

/**
see https://github.com/matter-labs/zksync-era/blob/main/core/lib/types/src/block.rs#L90

| Field                        | Type            | Size (bytes)    | RLP size (bytes) | RLP size (bits) |
|------------------------------|-----------------|-----------------|------------------|-----------------|
| number                       | big int scalar  | variable        | <= 5             | <= 40           |
| timestamp                    | big int scalar  | variable        | <= 9             | <= 72           |
| parentHash                   | 256 bits        | 32              | 33               | 264             |
 */
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockHeaderTrace<F: Field> {
    pub number: RlpFieldTrace<F>,
    pub timestamp: RlpFieldTrace<F>,
    pub parent_hash: RlpFieldTrace<F>,
    pub block_hash: RlcFixedTrace<F>,

    pub len_trace: RlcTrace<F>,
}

type BlockHeaderFieldWitness<F> = RlpArrayTraceWitness<F>;

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockHeaderTraceWitness<F: Field> {
    pub rlp_witness: BlockHeaderFieldWitness<F>,
    pub block_hash: Vec<AssignedValue<F>>,
    pub block_hash_query_idx: usize,
    pub txs_hash: Vec<AssignedBytes<F>>,
}

impl<F: Field> BlockHeaderFieldWitness<F> {
    pub fn get_number(&self) -> &RlpFieldWitness<F> {
        &self.field_witness[0]
    }
    pub fn get_timestamp(&self) -> &RlpFieldWitness<F> {
        &self.field_witness[1]
    }
    pub fn get_parent_hash(&self) -> &RlpFieldWitness<F> {
        &self.field_witness[2]
    }
}

// impl<F: Field> ContainsParallelizableKeccakQueries for ZkSyncEraBlockHeaderTraceWitness<F> {
//     // Currently all indices are with respect to `keccak.var_len_queries`
//     fn shift_query_indices(&mut self, _: usize, var_shift: usize) {
//         self.block_hash_query_idx += var_shift;
//     }
// }

pub trait ZkSyncEraBlockHeaderChip<F: Field> {
    /// Takes the variable length RLP encoded block header, padded with 0s to the maximum possible block header RLP length, and outputs the decomposition into block header fields.
    ///
    /// In addition, the keccak block hash of the block is calculated.
    ///
    /// Assumes `block_header` and `block_header_assigned` have the same values as bytes. The former is only used for faster witness generation.
    ///
    /// This is the preparation step that computes the witnesses. This MUST be done in `FirstPhase`.
    /// The accompanying `decompose_block_header_finalize` must be called in `SecondPhase` to constrain the RLCs associated to the RLP decoding.
    fn decompose_block_header_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        header: ZkSyncEraBlockHeaderInputAssigned<F>,
    ) -> ZkSyncEraBlockHeaderTraceWitness<F>;

    fn decompose_block_headers_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        headers_input: ZkSyncEraBlockHeadersInputAssigned<F>,
    ) -> Vec<ZkSyncEraBlockHeaderTraceWitness<F>>
    where
        Self: Sync,
    {
        let ctx = thread_pool.main(FIRST_PHASE);
        headers_input
            .headers
            .into_iter()
            .map(|block_header| self.decompose_block_header_phase0(ctx, keccak, block_header))
            .collect()
        // parallelize_keccak_phase0(
        //     thread_pool,
        //     keccak,
        //     block_headers,
        //     |ctx, keccak, block_header| {
        //         self.decompose_block_header_phase0(ctx, keccak, &block_header)
        //     },
        // )
    }

    /// Takes the variable length RLP encoded block header, padded with 0s to the maximum possible block header RLP length, and outputs the decomposition into block header fields.
    ///
    /// In addition, the keccak block hash of the block is calculated.
    ///
    /// Assumes `block_header` and `block_header_assigned` have the same values as bytes. The former is only used for faster witness generation.
    ///
    /// This is the finalization step that constrains RLC concatenations.
    /// This should be called after `decompose_block_header_phase0`.
    /// This MUST be done in `SecondPhase`.
    ///
    /// WARNING: This function is not thread-safe unless you call `load_rlc_cache` ahead of time.
    fn decompose_block_header_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: ZkSyncEraBlockHeaderTraceWitness<F>,
    ) -> ZkSyncEraBlockHeaderTrace<F>;

    /// Makes multiple calls to `decompose_block_header_phase1` in parallel threads. Should be called in SecondPhase.
    fn decompose_block_headers_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<ZkSyncEraBlockHeaderTraceWitness<F>>,
    ) -> Vec<ZkSyncEraBlockHeaderTrace<F>>;
}

impl<'chip, F: Field> ZkSyncEraBlockHeaderChip<F> for EthChip<'chip, F> {
    fn decompose_block_header_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        header: ZkSyncEraBlockHeaderInputAssigned<F>,
    ) -> ZkSyncEraBlockHeaderTraceWitness<F> {
        assert_eq!(header.block_header.len(), BLOCK_HEADER_RLP_MAX_BYTES);

        let rlp_witness: BlockHeaderFieldWitness<F> = self.rlp().decompose_rlp_array_phase0(
            ctx,
            header.block_header,
            &BLOCK_HEADER_MAX_FIELD_LENS,
            true,
        );

        // The first tx is a virtual tx, which is only used to generate txs_rolling_hash.
        let mut left_leaf = load_bytes(ctx, H256::zero().as_bytes());

        for right_leaf in header.txs_hash.clone().into_iter() {
            // splice left leaf and right leaf
            let left_node_concat: Vec<AssignedValue<F>> =
                [left_leaf.to_vec(), right_leaf.to_vec()].concat();
            let left_node_concat =
                ctx.assign_witnesses(left_node_concat.into_iter().map(|x| *x.value()));
            assert_eq!(left_node_concat.len(), 64);

            // keccak hash of left node concat and get idx
            let left_node_hash_idx =
                keccak.keccak_fixed_len(ctx, self.gate(), left_node_concat, None);
            let left_node_hash_bytes =
                keccak.fixed_len_queries[left_node_hash_idx].output_assigned.clone();
            let left_node_product =
                get_hash_bytes_inner_product(ctx, self.gate(), &left_node_hash_bytes);

            // If right leaf is empty, the value of left node is consistent with the value of left leaf.
            let left_node_consistent_left_leaf_product =
                get_hash_bytes_inner_product(ctx, self.gate(), &left_leaf);

            let right_leaf_is_empty = is_zero_vec(ctx, self.gate(), &right_leaf);

            let left_node_product = self.gate().select(
                ctx,
                left_node_consistent_left_leaf_product,
                left_node_product,
                right_leaf_is_empty,
            );

            left_leaf = if right_leaf_is_empty.value
                == halo2_base::halo2_proofs::plonk::Assigned::Trivial(F::zero())
            {
                // left leaf will be updated to left node hash
                left_node_hash_bytes
            } else {
                // left leaf will be consistent with the value of the original left leaf
                left_leaf
            };

            left_leaf = ctx.assign_witnesses(left_leaf.into_iter().map(|x| *x.value()));
            assert_eq!(left_leaf.len(), 32);

            let left_leaf_product = get_hash_bytes_inner_product(ctx, self.gate(), &left_leaf);

            ctx.constrain_equal(&left_node_product, &left_leaf_product);
        }

        let block_num_bytes = &rlp_witness.get_number().field_cells;
        let block_num_len = rlp_witness.get_number().field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 32);

        let block_time_stamp_bytes = &rlp_witness.get_timestamp().field_cells;
        let block_time_stamp_len = rlp_witness.get_timestamp().field_len;
        let block_time_stamp = bytes_be_var_to_fixed(
            ctx,
            self.gate(),
            block_time_stamp_bytes,
            block_time_stamp_len,
            32,
        );

        let parent_hash = &rlp_witness.get_parent_hash().field_cells;

        let block_hash_query_idx = keccak.keccak_fixed_len(
            ctx,
            self.gate(),
            [
                block_number.clone(),
                block_time_stamp.clone(),
                parent_hash.clone(),
                left_leaf.clone(),
            ]
            .concat(),
            None,
        );

        let block_hash = keccak.fixed_len_queries[block_hash_query_idx].output_assigned.clone();
        ZkSyncEraBlockHeaderTraceWitness {
            rlp_witness,
            block_hash,
            block_hash_query_idx,
            txs_hash: header.txs_hash,
        }
    }

    fn decompose_block_header_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: ZkSyncEraBlockHeaderTraceWitness<F>,
    ) -> ZkSyncEraBlockHeaderTrace<F> {
        let trace = self.rlp().decompose_rlp_array_phase1(ctx, witness.rlp_witness, true);
        let block_hash = self.keccak_fixed_len_rlcs()[witness.block_hash_query_idx].1.clone();
        let [number, timestamp, parent_hash]: [RlpFieldTrace<F>; NUM_BLOCK_HEADER_FIELDS] =
            trace.field_trace.try_into().unwrap();
        ZkSyncEraBlockHeaderTrace {
            number,
            timestamp,
            parent_hash,
            block_hash,
            len_trace: trace.len_trace,
        }
    }

    fn decompose_block_headers_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<ZkSyncEraBlockHeaderTraceWitness<F>>,
    ) -> Vec<ZkSyncEraBlockHeaderTrace<F>> {
        assert!(!witnesses.is_empty());
        let ctx = thread_pool.rlc_ctx_pair();
        // to ensure thread-safety of the later calls, we load rlc_cache to the max length first.
        // assuming this is called after `decompose_block_header_chain_phase0`, all headers should be same length = max_len
        let cache_bits = bit_length(witnesses[0].rlp_witness.rlp_array.len() as u64);
        self.rlc().load_rlc_cache(ctx, self.gate(), cache_bits);
        witnesses
            .into_iter()
            .map(|witness| {
                let ctx = thread_pool.rlc_ctx_pair();
                self.decompose_block_header_phase1(ctx, witness)
            })
            .collect()
        // now multi-threading:
        // parallelize_phase1(thread_pool, witnesses, |(ctx_gate, ctx_rlc), witness| {
        //     // self.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness, block_header_config)
        //     self.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness)
        // })
    }
}
