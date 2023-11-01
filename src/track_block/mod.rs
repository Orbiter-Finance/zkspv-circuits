use ark_std::{end_timer, start_timer};
use std::cell::RefCell;

use ethers_core::types::{Block, H256};
use ethers_providers::{Http, Provider};
use futures::AsyncReadExt;
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::bit_length;
use halo2_base::{AssignedValue, Context};
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::block_header::{
    get_block_header_config, BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace,
    EthBlockHeaderTraceWitness,
};
use crate::keccak::{
    parallelize_keccak_phase0, FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs,
};
use crate::mpt::AssignedBytes;
use crate::providers::get_block_track_input;
use crate::rlp::builder::{parallelize_phase1, RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::FIRST_PHASE;
use crate::rlp::RlpChip;
use crate::storage::EthStorageChip;
use crate::track_block::util::TrackBlockConstructor;
use crate::util::helpers::bytes_to_u8;
use crate::util::{bytes_be_to_u128, AssignedH256};
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, Network, ETH_LOOKUP_BITS};

mod tests;
pub mod util;

#[derive(Clone, Debug)]
pub struct EthTrackBlockInput {
    pub block: Vec<Block<H256>>,
    pub block_number: Vec<u64>,
    pub block_hash: Vec<H256>,
    // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockInputAssigned {
    pub block_header: Vec<Vec<u8>>,
}

impl EthTrackBlockInput {
    pub fn assign<F: Field>(self, _ctx: &mut Context<F>) -> EthTrackBlockInputAssigned {
        EthTrackBlockInputAssigned { block_header: self.block_header }
    }
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockCircuit {
    pub inputs: EthTrackBlockInput,
    pub block_header_config: BlockHeaderConfig,
}

impl EthTrackBlockCircuit {
    pub fn from_provider(provider: &Provider<Http>, constructor: TrackBlockConstructor) -> Self {
        let inputs = get_block_track_input(provider, &constructor);
        let block_header_config = get_block_header_config(&constructor.network);
        Self { inputs, block_header_config }
    }
}

impl EthPreCircuit for EthTrackBlockCircuit {
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
        let (witness, digest) = chip.parse_track_block_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            &self.block_header_config,
        );

        let EIP1186ResponseDigest { track_blocks_info } = digest;

        let assigned_instances = track_blocks_info
            .iter()
            .flat_map(|block| block.block_hash.into_iter().chain([block.block_number]))
            .collect_vec();

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
                let _trace = chip.parse_track_block_proof_from_block_phase1(builder, witness);
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct TrackBlockInfo<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub track_blocks_info: Vec<TrackBlockInfo<F>>,
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockTrace<F: Field> {
    pub blocks_trace: Vec<EthBlockHeaderTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockTraceWitness<F: Field> {
    pub blocks_witness: Vec<EthBlockHeaderTraceWitness<F>>,
}

pub trait EthTrackBlockChip<F: Field> {
    // ================= FIRST PHASE ================

    fn parse_track_block_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthTrackBlockInputAssigned,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthTrackBlockTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    // ================= SECOND PHASE ================

    fn parse_track_block_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: EthTrackBlockTraceWitness<F>,
    ) -> EthTrackBlockTrace<F>
    where
        Self: EthBlockHeaderChip<F>;
}

impl<'chip, F: Field> EthTrackBlockChip<F> for EthChip<'chip, F> {
    // ================= FIRST PHASE ================

    fn parse_track_block_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthTrackBlockInputAssigned,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthTrackBlockTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let mut track_blocks_info: Vec<TrackBlockInfo<F>> = Vec::new();

        // parallelize witness for blocks
        let blocks_witness = parallelize_keccak_phase0(
            thread_pool,
            keccak,
            input.block_header.clone(),
            |ctx, keccak, block_header| {
                let mut block_header = block_header.to_vec();
                block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);
                self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config)
            },
        );

        let ctx = thread_pool.main(FIRST_PHASE);

        for block_witness in blocks_witness.clone() {
            track_blocks_info.push(TrackBlockInfo {
                block_hash: bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash)
                    .to_vec()
                    .try_into()
                    .unwrap(),
                block_number: self.rlp_field_witnesses_to_uint(
                    ctx,
                    vec![&block_witness.get_number()],
                    vec![8],
                )[0],
            });
        }

        let digest = EIP1186ResponseDigest { track_blocks_info };

        (EthTrackBlockTraceWitness { blocks_witness }, digest)
    }

    // ================= SECOND PHASE ================

    fn parse_track_block_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: EthTrackBlockTraceWitness<F>,
    ) -> EthTrackBlockTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        assert!(!witnesses.blocks_witness.is_empty());
        let ctx = thread_pool.rlc_ctx_pair();

        let cache_bits = bit_length(witnesses.blocks_witness[0].rlp_witness.rlp_array.len() as u64);
        self.rlc().load_rlc_cache(ctx, self.gate(), cache_bits);

        let blocks_trace = parallelize_phase1(
            thread_pool,
            witnesses.blocks_witness,
            |(ctx_gate, ctx_rlc), block_witness| {
                self.decompose_block_header_phase1((ctx_gate, ctx_rlc), block_witness)
            },
        );

        EthTrackBlockTrace { blocks_trace }
    }
}
