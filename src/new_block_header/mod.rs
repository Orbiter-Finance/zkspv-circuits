use core::{
    iter::{self, once},
    marker::PhantomData,
};
use std::cell::RefCell;

use ethers_providers::{Http, Provider};
use halo2_base::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    utils::fs::gen_srs,
};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::QuantumCell::{Constant, Existing};
use halo2_base::utils::bit_length;
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::{ArbitrumNetwork, ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, EthereumNetwork, EthPreCircuit, Network, OptimismNetwork, ZkSyncEraNetwork};
use crate::keccak::{ContainsParallelizableKeccakQueries, FixedLenRLCs, FnSynthesize, KeccakChip, parallelize_keccak_phase0, VarLenRLCs};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness};
use crate::rlp::builder::{parallelize_phase1, RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{FIRST_PHASE, RLC_PHASE, RlcContextPair, RlcFixedTrace, RlcTrace};
use crate::util::{bytes_be_to_u128, bytes_be_var_to_fixed};
use crate::util::helpers::array_to_slice_with_4;

#[cfg(feature = "aggregation")]
pub mod aggregation;
#[cfg(all(feature = "aggregation", feature = "providers"))]
pub mod helper;
mod tests;

const NUM_BLOCK_HEADER_FIELDS: usize = 17;
const BLOCK_NUMBER_MAX_BYTES:usize = 4;

/// Config
#[derive(Clone, Debug)]
pub struct BlockHeaderConfig {
    extra_data_max_bytes: usize,
    extra_data_rlp_max_bytes: usize,

    /// This is the minimum possible RLP byte length of a block header *at any block* (including pre EIPs)
    block_header_rlp_min_bytes: usize,

    /// The maximum possible RLP byte length of a block header *at any block* (including all EIPs).
    /// Provided that the total length is < 256^2, this will be 1 + 2 + sum(max RLP byte length of each field)
    block_header_rlp_max_bytes: usize,

    /**
    | Field                        | Type            | Size (bytes)    | RLP size (bytes) | RLP size (bits) |
    |------------------------------|-----------------|-----------------|------------------|-----------------|
    | parentHash                   | 256 bits        | 32              | 33               | 264             |
    | ommersHash                   | 256 bits        | 32              | 33               | 264             |
    | beneficiary                  | 160 bits        | 20              | 21               | 168             |
    | stateRoot                    | 256 bits        | 32              | 33               | 264             |
    | transactionsRoot             | 256 bits        | 32              | 33               | 264             |
    | receiptsRoot                 | 256 bits        | 32              | 33               | 264             |
    | logsBloom                    | 256 bytes       | 256             | 259              | 2072            |
    | difficulty                   | big int scalar  | variable        | 8                | 64              |
    | number                       | big int scalar  | variable        | <= 5             | <= 40           |
    | gasLimit                     | big int scalar  | variable        | 5                | 40              |
    | gasUsed                      | big int scalar  | variable        | <= 5             | <= 40           |
    | timestamp                    | big int scalar  | variable        | 5                | 40              |
    | extraData (Mainnet)          | up to 256 bits  | variable, <= 32 | <= 33            | <= 264          |
    | mixHash                      | 256 bits        | 32              | 33               | 264             |
    | nonce                        | 64 bits         | 8               | 9                | 72              |
    | basefee (post-1559)          | big int scalar  | variable        | <= 6             | <= 48           |
    | withdrawalsRoot (post-4895) | 256 bits        | 32              | 33               | 264             |
     */
    header_fields_max_bytes: Vec<usize>,

    /// The maximum number of bytes it takes to represent a block number, without any RLP encoding.
    block_number_max_bytes: usize,
}

impl BlockHeaderConfig {
    fn new(
        extra_data_max_bytes: usize,
        block_header_rlp_min_bytes: usize,
        header_fields_max_bytes: Vec<usize>,
    ) -> BlockHeaderConfig {
        let extra_data_rlp_max_bytes = extra_data_max_bytes + 1;
        let block_header_rlp_max_bytes = 1 + 2 + (521 + extra_data_max_bytes + 33);
        let block_number_max_bytes = header_fields_max_bytes[8];
        BlockHeaderConfig {
            extra_data_max_bytes,
            extra_data_rlp_max_bytes,
            block_header_rlp_min_bytes,
            block_header_rlp_max_bytes,
            header_fields_max_bytes,
            block_number_max_bytes,
        }
    }
}

pub fn get_block_header_config(network: &Network) -> BlockHeaderConfig {
    let block_header_rlp_min_bytes = 479;


    let block_header_config = match network {
        Network::Ethereum(network) => {
            match network {
                EthereumNetwork::Mainnet => {
                    let extra_data_max_bytes = 97;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
                EthereumNetwork::Goerli => {
                    let extra_data_max_bytes = 32;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
            }
        }
        Network::Arbitrum(network) => {
            match network {
                ArbitrumNetwork::Mainnet => {
                    let extra_data_max_bytes = 32;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 7, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
                ArbitrumNetwork::Goerli => {
                    let extra_data_max_bytes = 32;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 7, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
            }
        }
        Network::Optimism(network) => {
            match network {
                OptimismNetwork::Mainnet => {
                    let extra_data_max_bytes = 97;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
                OptimismNetwork::Goerli => {
                    let extra_data_max_bytes = 32;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
            }
        }
        Network::ZkSync(network) => {
            match network {
                ZkSyncEraNetwork::Mainnet => {
                    let extra_data_max_bytes = 97;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
                ZkSyncEraNetwork::Goerli => {
                    let extra_data_max_bytes = 32;
                    let header_fields_max_bytes = vec![32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, extra_data_max_bytes, 32, 8, 6, 32];
                    BlockHeaderConfig::new(
                        extra_data_max_bytes,
                        block_header_rlp_min_bytes,
                        header_fields_max_bytes)
                }
            }
        }
    };
    block_header_config
}

/// Body
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EthBlockHeaderTrace<F: Field> {
    // pub rlp_trace: RlcTrace<F>,
    pub parent_hash: RlpFieldTrace<F>,
    pub ommers_hash: RlpFieldTrace<F>,
    pub beneficiary: RlpFieldTrace<F>,
    pub state_root: RlpFieldTrace<F>,
    pub transactions_root: RlpFieldTrace<F>,
    pub receipts_root: RlpFieldTrace<F>,
    pub logs_bloom: RlpFieldTrace<F>,
    pub difficulty: RlpFieldTrace<F>,
    pub number: RlpFieldTrace<F>,
    pub gas_limit: RlpFieldTrace<F>,
    pub gas_used: RlpFieldTrace<F>,
    pub timestamp: RlpFieldTrace<F>,
    pub extra_data: RlpFieldTrace<F>,
    pub mix_hash: RlpFieldTrace<F>,
    pub nonce: RlpFieldTrace<F>,
    pub basefee: RlpFieldTrace<F>,
    // this is 0 (or undefined) for pre-EIP1559 (London) blocks
    pub withdrawals_root: RlpFieldTrace<F>,
    // this is 0 (or undefined) for pre-EIP4895 (Shapella) blocks (before block number 1681338455)
    // the user will have to separately determine whether the block is EIP1559 or not
    pub block_hash: RlcFixedTrace<F>,

    // pub prefix: AssignedValue<F>,
    pub len_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockHeaderTraceWitness<F: Field> {
    pub rlp_witness: RlpArrayTraceWitness<F>,
    pub block_hash: Vec<AssignedValue<F>>,
    pub block_hash_query_idx: usize,
}

impl<F: Field> EthBlockHeaderTraceWitness<F> {
    pub fn get_parent_hash(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[0]
    }
    pub fn get_ommers_hash(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[1]
    }
    pub fn get_beneficiary(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[2]
    }
    pub fn get_state_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[3]
    }
    pub fn get_transactions_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[4]
    }
    pub fn get_receipts_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[5]
    }
    pub fn get_logs_bloom(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[6]
    }
    pub fn get_difficulty(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[7]
    }
    pub fn get_number(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[8]
    }
    pub fn get_gas_limit(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[9]
    }
    pub fn get_gas_used(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[10]
    }
    pub fn get_timestamp(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[11]
    }
    pub fn get_extra_data(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[12]
    }
    pub fn get_mix_hash(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[13]
    }
    pub fn get_nonce(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[14]
    }
    pub fn get_basefee(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[15]
    }
    pub fn get_withdrawals_root(&self) -> &RlpFieldWitness<F> {
        &self.rlp_witness.field_witness[16]
    }
    pub fn get_index(&self, idx: usize) -> Option<&RlpFieldWitness<F>> {
        self.rlp_witness.field_witness.get(idx)
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthBlockHeaderTraceWitness<F> {
    // Currently all indices are with respect to `keccak.var_len_queries`
    fn shift_query_indices(&mut self, _: usize, var_shift: usize) {
        self.block_hash_query_idx += var_shift;
    }
}

pub trait EthBlockHeaderChip<F: Field> {
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
        block_header_rlp: &[u8],
        network: Network,
        block_header_config: &BlockHeaderConfig,
    ) -> EthBlockHeaderTraceWitness<F>;

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
        witness: EthBlockHeaderTraceWitness<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> EthBlockHeaderTrace<F>;

    /// Makes multiple calls to `decompose_block_header_phase0` in parallel threads. Should be called in FirstPhase.
    fn decompose_block_headers_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        block_headers: Vec<Vec<u8>>,
        network: Network,
        block_header_config: &BlockHeaderConfig,
    ) -> Vec<EthBlockHeaderTraceWitness<F>>
        where
            Self: Sync,
    {
        parallelize_keccak_phase0(
            thread_pool,
            keccak,
            block_headers,
            |ctx, keccak, block_header| {
                self.decompose_block_header_phase0(ctx, keccak, &block_header, network, block_header_config)
            },
        )
    }

    /// Makes multiple calls to `decompose_block_header_phase1` in parallel threads. Should be called in SecondPhase.
    fn decompose_block_headers_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<EthBlockHeaderTraceWitness<F>>,
        block_header_config: &BlockHeaderConfig,
    ) -> Vec<EthBlockHeaderTrace<F>>;

    /// Takes a list of (purported) RLP encoded block headers and
    /// decomposes each header into it's fields.
    /// `headers[0]` is the earliest block.
    ///
    /// This is the preparation step that computes the witnesses. This MUST be done in `FirstPhase`.
    /// The accompanying `decompose_block_header_chain_phase1` must be called in `SecondPhase` to constrain the RLCs associated to the RLP decoding.
    fn decompose_block_header_chain_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        block_headers: Vec<Vec<u8>>,
        network: Network,
        block_header_config: &BlockHeaderConfig,
    ) -> Vec<EthBlockHeaderTraceWitness<F>>
        where
            Self: Sync,
    {
        self.decompose_block_headers_phase0(thread_pool, keccak, block_headers, network, block_header_config)
    }

    /// Takes a list of `2^max_depth` (purported) RLP encoded block headers.
    /// Decomposes each header into it's fields.
    /// `headers[0]` is the earliest block
    ///
    /// - If `num_blocks_minus_one = (num_blocks_minus_one, indicator)` is not None, then the circuit checks that the first `num_blocks := num_blocks_minus_one + 1` block headers form a chain: meaning that the parent hash of block i + 1 equals the hash of block i.
    /// - `indicator` is a vector with index `i` equal to `i == num_blocks - 1 ? 1 : 0`.
    /// - Otherwise if `num_blocks` is None, the circuit checks that all `headers` form a hash chain.
    ///
    /// Assumes that `0 <= num_blocks_minus_one < 2^max_depth`.
    ///
    /// This is the finalization step that constrains RLC concatenations. In this step the hash chain is actually constrained.
    /// This should be called after `decompose_block_header_chain_phase0`.
    /// This MUST be done in `SecondPhase`.
    fn decompose_block_header_chain_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<EthBlockHeaderTraceWitness<F>>,
        num_blocks_minus_one: Option<(AssignedValue<F>, Vec<AssignedValue<F>>)>,
        block_header_config: &BlockHeaderConfig,
    ) -> Vec<EthBlockHeaderTrace<F>>;
}

impl<'chip, F: Field> EthBlockHeaderChip<F> for EthChip<'chip, F> {
    fn decompose_block_header_phase0(
        &self,
        ctx: &mut Context<F>, // ctx_gate in FirstPhase
        keccak: &mut KeccakChip<F>,
        block_header: &[u8],
        network: Network,
        block_header_config: &BlockHeaderConfig,
    ) -> EthBlockHeaderTraceWitness<F> {
        assert_eq!(block_header.len(), block_header_config.block_header_rlp_max_bytes);
        let block_header_assigned =
            ctx.assign_witnesses(block_header.iter().map(|byte| F::from(*byte as u64)));
        let rlp_witness =
            self.rlp().decompose_rlp_array_phase0(ctx, block_header_assigned, &block_header_config.header_fields_max_bytes, true); // `is_variable_len = true` because RLP can have between 15 to 17 fields, depending on which EIPs are active at that block

        let block_hash_query_idx = keccak.keccak_var_len(
            ctx,
            self.range(),
            rlp_witness.rlp_array.clone(), // this is `block_header_assigned`
            Some(block_header.to_vec()),
            rlp_witness.rlp_len,
            block_header_config.block_header_rlp_min_bytes,
        );
        let block_hash = keccak.var_len_queries[block_hash_query_idx].output_assigned.clone();
        EthBlockHeaderTraceWitness { rlp_witness, block_hash, block_hash_query_idx }
    }

    fn decompose_block_header_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthBlockHeaderTraceWitness<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> EthBlockHeaderTrace<F> {
        let trace = self.rlp().decompose_rlp_array_phase1(ctx, witness.rlp_witness, true);
        let block_hash = self.keccak_var_len_rlcs()[witness.block_hash_query_idx].1;
        // The block field of each network may be different.
        // let number_field = block_header_config.header_fields_max_bytes.len();
        // Base fee per unit gas only after London
        let [parent_hash, ommers_hash, beneficiary, state_root, transactions_root, receipts_root, logs_bloom, difficulty, number, gas_limit, gas_used, timestamp, extra_data, mix_hash, nonce, basefee, withdrawals_root]: [RlpFieldTrace<F>; NUM_BLOCK_HEADER_FIELDS]
            = trace.field_trace.try_into().unwrap();


        EthBlockHeaderTrace {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            mix_hash,
            nonce,
            basefee,
            withdrawals_root,
            block_hash,
            len_trace: trace.len_trace,
        }
    }

    fn decompose_block_headers_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<EthBlockHeaderTraceWitness<F>>,
        block_header_config: &BlockHeaderConfig,
    ) -> Vec<EthBlockHeaderTrace<F>> {
        assert!(!witnesses.is_empty());
        let ctx = thread_pool.rlc_ctx_pair();
        // to ensure thread-safety of the later calls, we load rlc_cache to the max length first.
        // assuming this is called after `decompose_block_header_chain_phase0`, all headers should be same length = max_len
        let cache_bits = bit_length(witnesses[0].rlp_witness.rlp_array.len() as u64);
        self.rlc().load_rlc_cache(ctx, self.gate(), cache_bits);
        // now multi-threading:
        parallelize_phase1(thread_pool, witnesses, |(ctx_gate, ctx_rlc), witness| {
            self.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness, block_header_config)
        })
    }

    fn decompose_block_header_chain_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<EthBlockHeaderTraceWitness<F>>,
        num_blocks_minus_one: Option<(AssignedValue<F>, Vec<AssignedValue<F>>)>,
        block_header_config: &BlockHeaderConfig,
    ) -> Vec<EthBlockHeaderTrace<F>> {
        assert!(!witnesses.is_empty());
        let traces = self.decompose_block_headers_phase1(thread_pool, witnesses, block_header_config);
        let ctx_gate = thread_pool.gate_builder.main(RLC_PHASE);
        let thirty_two = self.gate().get_field_element(32);
        // record for each idx whether hash of headers[idx] is in headers[idx + 1]
        if let Some((num_blocks_minus_one, indicator)) = num_blocks_minus_one {
            let mut hash_checks = Vec::with_capacity(traces.len() - 1);
            for idx in 0..traces.len() - 1 {
                let hash_check = self.gate().is_equal(
                    ctx_gate,
                    traces[idx].block_hash.rlc_val,
                    traces[idx + 1].parent_hash.field_trace.rlc_val,
                );
                hash_checks.push(hash_check);
                self.gate().assert_is_const(
                    ctx_gate,
                    &traces[idx + 1].parent_hash.field_trace.len,
                    &thirty_two,
                );
            }
            let hash_check_sums =
                self.gate().partial_sums(ctx_gate, hash_checks.iter().copied()).collect_vec();
            let hash_check_sum = self.gate().select_by_indicator(
                ctx_gate,
                once(Constant(F::zero())).chain(hash_check_sums.into_iter().map(Existing)),
                indicator,
            );
            ctx_gate.constrain_equal(&hash_check_sum, &num_blocks_minus_one);
        } else {
            for idx in 0..traces.len() - 1 {
                ctx_gate.constrain_equal(
                    &traces[idx].block_hash.rlc_val,
                    &traces[idx + 1].parent_hash.field_trace.rlc_val,
                );
                self.gate().assert_is_const(
                    ctx_gate,
                    &traces[idx + 1].parent_hash.field_trace.len,
                    &thirty_two,
                );
            }
        }

        traces
    }
}

/// Given a block header chain `chain` of fixed length `2^max_depth`, returns
/// ```
/// (prev_block_hash, end_block_hash, start_block_number || end_block_number)
/// ```
/// where
/// ```
/// prev_block_hash = chain[0].parent_hash,
/// end_block_hash = chain[num_blocks_minus_one].block_hash,
/// start_block_number = chain[0].number,
/// end_block_number = chain[num_blocks_minus_one].number
/// ```
/// The hashes are H256 that are represented as two u128
/// (we need them in 128 bits to fit in Bn254 scalar field).
///
/// The numbers are left padded by zeros to be exactly 4 bytes (u32); the two padded numbers are concatenated together to a u64.
///
/// `indicator` is the indicator for `num_blocks_minus_one`, where `indicator[i] = (i == end_block_number - start_block_number ? 1 : 0)`.
///
/// This function should be called in `FirstPhase`.
pub fn get_boundary_block_data<F: Field>(
    ctx: &mut Context<F>, // ctx_gate in FirstPhase
    gate: &impl GateInstructions<F>,
    chain: &[EthBlockHeaderTraceWitness<F>],
    indicator: &[AssignedValue<F>],
    block_header_config: &BlockHeaderConfig,
) -> ([AssignedValue<F>; 2], [AssignedValue<F>; 2], AssignedValue<F>) {
    let block_number_max_bytes = block_header_config.block_number_max_bytes;
    let prev_block_hash: [_; 2] =
        bytes_be_to_u128(ctx, gate, &chain[0].get_parent_hash().field_cells).try_into().unwrap();
    let end_block_hash: [_; 2] = {
        let end_block_hash_bytes = (0..32)
            .map(|idx| {
                gate.select_by_indicator(
                    ctx,
                    chain.iter().map(|header| header.block_hash[idx]),
                    indicator.iter().copied(),
                )
            })
            .collect_vec();
        bytes_be_to_u128(ctx, gate, &end_block_hash_bytes).try_into().unwrap()
    };

    // start_block_number || end_block_number
    let block_numbers = {
        debug_assert_eq!(chain[0].get_number().max_field_len, block_number_max_bytes);
        let start_block_number_bytes = bytes_be_var_to_fixed(
            ctx,
            gate,
            &chain[0].get_number().field_cells,
            chain[0].get_number().field_len,
            block_header_config.block_number_max_bytes,
        );
        // TODO: is there a way to do this without so many selects

        let end_block_number_bytes: [_; BLOCK_NUMBER_MAX_BYTES] =
            core::array::from_fn(|i| i).map(|idx| {
                gate.select_by_indicator(
                    ctx,
                    chain.iter().map(|header| header.get_number().field_cells[idx]),
                    indicator.iter().copied(),
                )
            });
        let end_block_number_len = gate.select_by_indicator(
            ctx,
            chain.iter().map(|header| header.get_number().field_len),
            indicator.iter().copied(),
        );
        let mut end_block_number_bytes = bytes_be_var_to_fixed(
            ctx,
            gate,
            &end_block_number_bytes,
            end_block_number_len,
            block_number_max_bytes,
        );
        let mut block_numbers_bytes = start_block_number_bytes;
        block_numbers_bytes.append(&mut end_block_number_bytes);
        let [block_numbers]: [_; 1] =
            bytes_be_to_u128(ctx, gate, &block_numbers_bytes).try_into().unwrap();
        block_numbers
    };

    (prev_block_hash, end_block_hash, block_numbers)
}

#[derive(Clone, Debug)]
/// The input datum for the block header chain circuit. It is used to generate a circuit.
pub struct EthBlockHeaderChainCircuit<F> {
    /// The private inputs, which are the RLP encodings of the block headers
    header_rlp_encodings: Vec<Vec<u8>>,
    num_blocks: u32,
    // num_blocks in [0, 2 ** max_depth)
    // The public inputs:
    // (prev_hash, end_hash, start_block_number, end_block_number, merkle_roots: [H256; max_depth + 1])
    // pub instance: EthBlockHeaderChainInstance,
    max_depth: usize,
    network: Network,
    _marker: PhantomData<F>,
}

impl<F: Field> EthBlockHeaderChainCircuit<F> {
    #[cfg(feature = "providers")]
    pub fn from_provider(
        provider: &Provider<Http>,
        network: Network,
        start_block_number: u32,
        num_blocks: u32,
        max_depth: usize,
    ) -> Self {
        let block_header_config = get_block_header_config(&network);
        let header_rlp_max_bytes = block_header_config.block_header_rlp_max_bytes;
        let mut block_rlps =
            crate::providers::get_blocks_input(provider, start_block_number, num_blocks, max_depth);
        for block_rlp in block_rlps.iter_mut() {
            block_rlp.resize(header_rlp_max_bytes, 0u8);
        }

        Self {
            header_rlp_encodings: block_rlps,
            num_blocks,
            max_depth,
            network,
            _marker: PhantomData,
        }
    }

    pub fn create(
        self,
        mut builder: RlcThreadBuilder<F>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<F, impl FnSynthesize<F>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        // KECCAK_ROWS should be set if prover = true
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();

        let ctx = builder.gate_builder.main(FIRST_PHASE);
        // ======== FIRST PHASE ===========
        // ==== Load private inputs =====
        let num_blocks = ctx.load_witness(F::from(self.num_blocks as u64));
        let num_blocks_minus_one = chip.gate().sub(ctx, num_blocks, Constant(F::one()));
        // `num_blocks_minus_one` should be < 2^max_depth.
        // We check this for safety, although it is not technically necessary because `num_blocks_minus_one` will equal the difference of the start, end block numbers, which are public inputs
        chip.range().range_check(ctx, num_blocks_minus_one, self.max_depth);

        let block_header_config = get_block_header_config(&self.network);

        // ==== Load RLP encoding and decode ====
        // The block header RLPs are assigned as witnesses in this function
        let block_chain_witness = chip.decompose_block_header_chain_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            self.header_rlp_encodings,
            self.network,
            &block_header_config,
        );
        // All keccaks must be done in FirstPhase, so we compute the merkle mountain range from the RLP decoded witnesses now
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let num_leaves_bits = chip.gate().num_to_bits(ctx, num_blocks, self.max_depth + 1);
        let block_hashes = block_chain_witness
            .iter()
            .map(|witness| {
                keccak.var_len_queries[witness.block_hash_query_idx].output_assigned.clone()
            })
            .collect_vec();
        // mountain range in bytes
        let mountain_range =
            keccak.merkle_mountain_range(ctx, chip.gate(), &block_hashes, &num_leaves_bits);
        let mountain_range = mountain_range
            .into_iter()
            .zip(num_leaves_bits.into_iter().rev())
            .flat_map(|(hash_bytes, bit)| {
                // convert bytes32 to two u128
                let hash_u128s: [_; 2] =
                    bytes_be_to_u128(ctx, chip.gate(), &hash_bytes).try_into().unwrap();
                // if the bit is 0, then we set the hash root to 0
                hash_u128s.map(|hash_u128| chip.gate().mul(ctx, hash_u128, bit))
            })
            .collect_vec();

        let indicator =
            chip.gate().idx_to_indicator(ctx, num_blocks_minus_one, block_chain_witness.len());
        let (prev_block_hash, end_block_hash, block_numbers) =
            get_boundary_block_data(ctx, chip.gate(), &block_chain_witness, &indicator, &block_header_config);
        let assigned_instances = iter::empty()
            .chain(prev_block_hash)
            .chain(end_block_hash)
            .chain(iter::once(block_numbers))
            .chain(mountain_range)
            .collect_vec();

        EthCircuitBuilder::new(
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
                let _block_chain_trace = chip.decompose_block_header_chain_phase1(
                    builder,
                    block_chain_witness,
                    Some((num_blocks_minus_one, indicator)),
                    &block_header_config,
                );
            },
        )
    }
}

impl EthPreCircuit for EthBlockHeaderChainCircuit<Fr> {
    fn create(
        self,
        builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        self.create(builder, break_points)
    }
}
