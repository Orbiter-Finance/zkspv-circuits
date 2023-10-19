use ark_std::{end_timer, start_timer};
use std::cell::RefCell;

use ethers_core::types::{Block, H256};
use ethers_providers::{Http, Provider};
use futures::AsyncReadExt;
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
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
    pub target_index: u64,
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockInputAssigned<F: Field> {
    pub block_header: Vec<Vec<u8>>,
    pub target_index: AssignedValue<F>,
}

impl EthTrackBlockInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTrackBlockInputAssigned<F> {
        let target_index = (F::from(self.target_index)).try_into().unwrap();
        let target_index = ctx.load_witness(target_index);
        EthTrackBlockInputAssigned { block_header: self.block_header, target_index }
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

        let EIP1186ResponseDigest {
            start_block_hash,
            start_block_number,
            end_block_hash,
            end_block_number,
            target_block_hash,
            target_block_number,
        } = digest;

        let assigned_instances = start_block_hash
            .into_iter()
            .chain(end_block_hash)
            .chain(target_block_hash)
            .chain([start_block_number, end_block_number, target_block_number])
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
pub struct EIP1186ResponseDigest<F: Field> {
    pub start_block_hash: AssignedH256<F>,
    pub start_block_number: AssignedValue<F>,
    pub end_block_hash: AssignedH256<F>,
    pub end_block_number: AssignedValue<F>,
    pub target_block_hash: AssignedH256<F>,
    pub target_block_number: AssignedValue<F>,
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
        input: EthTrackBlockInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthTrackBlockTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    // ================= SECOND PHASE ================

    fn parse_track_block_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTrackBlockTraceWitness<F>,
    ) -> EthTrackBlockTrace<F>
    where
        Self: EthBlockHeaderChip<F>;
}

impl<'chip, F: Field> EthTrackBlockChip<F> for EthChip<'chip, F> {
    // ================= FIRST PHASE ================

    /// 1. last_hash <- first.block.hash
    /// 2. second.block.parent_hash == last_hash;last_hash <- second.block.hash
    /// 3...
    fn parse_track_block_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthTrackBlockInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthTrackBlockTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let mut start_block_hash: Vec<AssignedValue<F>> = Vec::new();
        let mut last_block_hash: Vec<AssignedValue<F>> = Vec::new();
        let mut target_block_hash: Vec<AssignedValue<F>> = Vec::new();

        // parallelize witness for blocks
        #[cfg(feature = "display")]
        let start_blocks = start_timer!(|| "parallelize witness for blocks");
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
        #[cfg(feature = "display")]
        end_timer!(start_blocks);

        let ctx = thread_pool.main(FIRST_PHASE);
        #[cfg(feature = "display")]
        let start = start_timer!(|| "blocks_witness");
        let zero = ctx.load_constant(F::from(0));
        let mut start_block_number = zero;
        let mut end_block_number = zero;
        let mut target_block_number = zero;
        // The maximum total length of a single round calculation is 256, so make sure it is u8 type data.
        let target_index = bytes_to_u8(&input.target_index);
        for (i, block_witness) in blocks_witness.iter().enumerate() {
            if i != 0 {
                let temp_last_block_hash = last_block_hash.to_vec();

                // Get the parent hash from the current block header
                let parent_hash = bytes_be_to_u128(
                    ctx,
                    self.gate(),
                    &block_witness.get_parent_hash().field_cells,
                );
                for (pre_block_hash, parent_hash) in
                    temp_last_block_hash.iter().zip(parent_hash.iter())
                {
                    ctx.constrain_equal(pre_block_hash, parent_hash);
                }
            }

            last_block_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

            if i == 0 {
                start_block_hash = last_block_hash.to_vec();
                start_block_number = self.rlp_field_witnesses_to_uint(
                    ctx,
                    vec![&block_witness.get_number()],
                    vec![8],
                )[0];
            } else if i == blocks_witness.len() - 1 {
                end_block_number = self.rlp_field_witnesses_to_uint(
                    ctx,
                    vec![&block_witness.get_number()],
                    vec![8],
                )[0];
            }

            if i == target_index as usize {
                target_block_hash = last_block_hash.to_vec();
                target_block_number = self.rlp_field_witnesses_to_uint(
                    ctx,
                    vec![&block_witness.get_number()],
                    vec![8],
                )[0];
            }
        }
        #[cfg(feature = "display")]
        end_timer!(start);

        let digest = EIP1186ResponseDigest {
            start_block_hash: start_block_hash.to_vec().try_into().unwrap(),
            start_block_number,
            end_block_hash: last_block_hash.to_vec().try_into().unwrap(),
            end_block_number,
            target_block_hash: target_block_hash.try_into().unwrap(),
            target_block_number,
        };

        (EthTrackBlockTraceWitness { blocks_witness }, digest)
    }

    // ================= SECOND PHASE ================

    fn parse_track_block_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTrackBlockTraceWitness<F>,
    ) -> EthTrackBlockTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let blocks_trace = parallelize_phase1(
            thread_pool,
            witness.blocks_witness,
            |(ctx_gate, ctx_rlc), block_witness| {
                self.decompose_block_header_phase1((ctx_gate, ctx_rlc), block_witness)
            },
        );

        EthTrackBlockTrace { blocks_trace }
    }
}
