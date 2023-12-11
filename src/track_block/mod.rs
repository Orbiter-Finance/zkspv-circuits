use ark_std::{end_timer, start_timer};
use halo2_base::safe_types::RangeInstructions;
use halo2_base::QuantumCell::Constant;
use serde::Serialize;
use std::cell::RefCell;

use ethers_core::types::{Block, H256};
use ethers_providers::{Http, Provider, RetryClient};
use futures::AsyncReadExt;
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::utils::bit_length;
use halo2_base::{AssignedValue, Context};
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::arbitration::types::BatchBlocksInput;
use crate::block_header::{
    get_block_header_config, BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace,
    EthBlockHeaderTraceWitness,
};
use crate::keccak::tests::get_block_data_hashes_from_json;
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
use crate::util::helpers::{bytes_to_u8, get_block_batch_hashes, get_provider};
use crate::util::{
    bytes_be_to_u128, encode_h256_to_bytes_field, encode_merkle_path_to_field,
    h256_non_standard_tree_root_and_proof, AssignedH256,
};
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, Network, ETH_LOOKUP_BITS};

mod tests;
pub mod util;

#[derive(Clone, Debug, Serialize)]
pub struct BlockMerkleInclusionInputSingle {
    pub merkle_root: H256,
    pub proof: Vec<H256>,
    pub target_leaf: H256,
    pub path: Vec<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockMerkleInclusionInput {
    pub input: Vec<BlockMerkleInclusionInputSingle>,
}

#[derive(Clone, Debug)]
pub struct BlockMerkleInclusionInputAssigned<F: Field> {
    pub merkle_root: Vec<AssignedValue<F>>,
    pub proof: Vec<Vec<AssignedValue<F>>>,
    pub target_leaf: Vec<AssignedValue<F>>,
    pub path: Vec<AssignedValue<F>>,
}
#[derive(Clone, Debug)]
pub struct BLockMerkleInclusionWitness<F: Field> {
    pub input: Vec<BlockMerkleInclusionInputAssigned<F>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockMerkleInclusionCircuit {
    pub inclusion_proof: BlockMerkleInclusionInput,
    pub block_range_length: u64,
    pub block_batch_num: u64,
}

#[derive(Clone, Debug)]
pub struct BlockMerkleInclusionConstructor {
    pub start_block_num: u32,
    pub end_block_num: u32,
    pub target_block_num: u32,
}

impl BlockMerkleInclusionCircuit {
    pub fn from_json_object(batch_data: BatchBlocksInput) -> Self {
        let input = batch_data
            .batch_blocks_merkle
            .iter()
            .map(|batch| {
                let ((proof_root, proof, path), target_leaf) = (
                    h256_non_standard_tree_root_and_proof(
                        &batch.block_hash_batch,
                        batch.target_block_index,
                    ),
                    batch.block_hash_batch[batch.target_block_index as usize].clone(),
                );
                assert_eq!(proof_root, batch.block_batch_merkle_root);
                BlockMerkleInclusionInputSingle {
                    merkle_root: proof_root,
                    proof,
                    target_leaf,
                    path,
                }
            })
            .collect_vec();

        Self {
            inclusion_proof: BlockMerkleInclusionInput { input },
            block_range_length: batch_data.batch_blocks_merkle[0].block_hash_batch.len() as u64,
            block_batch_num: batch_data.batch_blocks_merkle.len() as u64,
        }
    }

    pub fn from_json() -> Self {
        let batch_data = get_block_data_hashes_from_json();
        Self::from_json_object(batch_data)
    }

    pub fn from_provider(
        network: &Network,
        constructors: &Vec<BlockMerkleInclusionConstructor>,
    ) -> Self {
        let provider = get_provider(network);

        // for constructor in constructors {
        //     let start_block_num = constructor.start_block_num;
        //     let end_block_num = constructor.end_block_num;
        //     let leaves =
        //         get_block_batch_hashes(&provider, start_block_num.clone(), end_block_num.clone());
        // }

        Self {
            inclusion_proof: BlockMerkleInclusionInput {
                input: constructors
                    .iter()
                    .map(|c| {
                        (
                            get_block_batch_hashes(&provider, c.start_block_num, c.end_block_num),
                            (c.target_block_num - c.start_block_num),
                        )
                    })
                    .collect_vec()
                    .iter()
                    .map(|(leaves, target_index)| {
                        let ((proof_root, proof, path), target_leaf) = (
                            h256_non_standard_tree_root_and_proof(leaves, *target_index),
                            leaves[*target_index as usize].clone(),
                        );
                        BlockMerkleInclusionInputSingle {
                            merkle_root: proof_root,
                            proof,
                            target_leaf,
                            path,
                        }
                    })
                    .collect_vec(),
            },
            block_range_length: (constructors[0].end_block_num - constructors[0].start_block_num
                + 1) as u64,
            block_batch_num: constructors.len() as u64,
        }
    }
}

impl EthPreCircuit for BlockMerkleInclusionCircuit {
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
        let assigned_input = chip.parse_merkle_proof_phase0(ctx, self.inclusion_proof);
        let result = assigned_input
            .input
            .iter()
            .map(|input| {
                keccak.verify_merkle_proof(
                    ctx,
                    &range.gate,
                    &input.merkle_root,
                    &input.proof,
                    &input.target_leaf,
                    &input.path,
                )
            })
            .collect_vec();

        let assigned_instances =
            result.iter().map(|r| r.0.iter().chain(r.1.iter()).cloned()).flatten().collect_vec();
        println!("BlockMerkleInclusionCircuit pis cnt {}", assigned_instances.len());
        for i in 0..result.len() {
            println!("result {} {:?}", i, result[i]);
        }

        EthCircuitBuilder::new(
            assigned_instances.clone(),
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            move |builder: &mut RlcThreadBuilder<Fr>,
                  rlp: RlpChip<Fr>,
                  keccak_rlcs: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {
                // ======== SECOND PHASE ===========
                let chip = EthChip::new(rlp, Some(keccak_rlcs));
                let _trace = chip.parse_merkle_proof_phase1(builder, assigned_instances);
            },
        )
    }
}

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
        provider: &Provider<RetryClient<Http>>,
        constructor: TrackBlockConstructor,
    ) -> Self {
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

    fn parse_merkle_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        input: BlockMerkleInclusionInput,
    ) -> BLockMerkleInclusionWitness<F>
    where
        Self: EthBlockHeaderChip<F>;

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

    fn parse_merkle_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        input: Vec<AssignedValue<F>>,
    ) -> Vec<AssignedValue<F>>
    where
        Self: EthBlockHeaderChip<F>;

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
    fn parse_merkle_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        input: BlockMerkleInclusionInput,
    ) -> BLockMerkleInclusionWitness<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let mut result =
            BLockMerkleInclusionWitness { input: Vec::with_capacity(input.input.capacity()) };
        input.input.into_iter().for_each(|input| {
            let merkle_root =
                ctx.assign_witnesses(encode_h256_to_bytes_field::<F>(input.merkle_root));
            let proof = input
                .proof
                .into_iter()
                .map(|p| ctx.assign_witnesses(encode_h256_to_bytes_field::<F>(p)))
                .collect_vec();
            let target_leaf =
                ctx.assign_witnesses(encode_h256_to_bytes_field::<F>(input.target_leaf));
            let path = ctx.assign_witnesses(encode_merkle_path_to_field::<F>(&input.path));
            result.input.push(BlockMerkleInclusionInputAssigned {
                merkle_root,
                proof,
                target_leaf,
                path,
            });
        });
        result
    }
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
    fn parse_merkle_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        input: Vec<AssignedValue<F>>,
    ) -> Vec<AssignedValue<F>>
    where
        Self: EthBlockHeaderChip<F>,
    {
        return input;
    }
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
