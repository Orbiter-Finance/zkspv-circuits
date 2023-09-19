use std::cell::RefCell;

use ethers_core::types::{Block, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::RangeChip;
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, EthPreCircuit, Network};
use crate::block_header::{BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness, get_block_header_config};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::providers::get_block_track_input;
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::FIRST_PHASE;
use crate::rlp::RlpChip;
use crate::util::{AssignedH256, bytes_be_to_u128};

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
    pub fn from_provider(
        provider: &Provider<Http>,
        block_number_interval: Vec<u64>,
        network: Network,
    ) -> Self {
        let inputs = get_block_track_input(
            provider,
            block_number_interval,
        );
        let block_header_config = get_block_header_config(&network);
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
            &self.block_header_config);

        let EIP1186ResponseDigest {
            last_block_hash,
        } = digest;

        let assigned_instances = last_block_hash
            .into_iter()
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
    pub last_block_hash: AssignedH256<F>,
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
        input: EthTrackBlockInputAssigned,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthTrackBlockTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>, {
        let ctx = thread_pool.main(FIRST_PHASE);
        let mut last_block_hash: Vec<AssignedValue<F>> = Vec::new();
        let mut blocks_witness = Vec::with_capacity(input.block_header.len());
        for (i, block_header) in input.block_header.iter().enumerate() {
            let mut block_header = block_header.to_vec();
            block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);

            // It has been checked whether keccak(rlp(block_header)) is equal to block_hash.
            // Therefore, there is no need to declare the qualification repeatedly.
            let block_witness = self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config);

            if i != 0 {
                let parent_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness.get_parent_hash().field_cells);
                for (pre_block_hash, parent_hash) in last_block_hash.iter().zip(parent_hash.iter()) {
                    ctx.constrain_equal(pre_block_hash, parent_hash);
                }
            }

            last_block_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);
            blocks_witness.push(block_witness);
        }

        let digest = EIP1186ResponseDigest {
            last_block_hash: last_block_hash.try_into().unwrap(),
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
            Self: EthBlockHeaderChip<F> {
        let mut blocks_trace = Vec::with_capacity(witness.blocks_witness.len());
        for block_witness in witness.blocks_witness {
            let block_trace = self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), block_witness);
            blocks_trace.push(block_trace);
        }

        EthTrackBlockTrace { blocks_trace }
    }
}

