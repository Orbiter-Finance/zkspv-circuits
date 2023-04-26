use std::{cell::RefCell, env::var};
use ethers_core::types::{Block, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::{GateInstructions, RangeChip};
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;
use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, Network};
use crate::block_header::{EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness, GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES};
use crate::keccak::{FixedLenRLCs, KeccakChip, VarLenRLCs, FnSynthesize};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::FIRST_PHASE;
use crate::rlp::RlpChip;
use crate::util::{AssignedH256, bytes_be_to_u128, EthConfigParams};

mod tests;

// Currently only available for L1
// 200 blocks take about an hour


#[derive(Clone, Debug)]
pub struct EthTrackBlockTraceWitness<F: Field> {
    pub block_witness: Vec<EthBlockHeaderTraceWitness<F>>,
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockTrace<F: Field> {
    pub block_trace: Vec<EthBlockHeaderTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub last_block_hash: AssignedH256<F>,
}


pub trait EthTrackBlockChip<F: Field> {
    fn parse_track_block_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthTrackBlockInputAssigned,
        network: Network,
    ) -> (EthTrackBlockTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>;


    fn parse_track_block_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTrackBlockTraceWitness<F>,
    ) -> EthTrackBlockTrace<F>
        where
            Self: EthBlockHeaderChip<F>;
}

impl<'chip, F: Field> EthTrackBlockChip<F> for EthChip<'chip, F> {
    fn parse_track_block_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthTrackBlockInputAssigned,
        network: Network,
    ) -> (EthTrackBlockTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>, {
        let ctx = thread_pool.main(FIRST_PHASE);
        let mut parent_hash:Vec<AssignedValue<F>> = Vec::new();
        let mut block_witness = Vec::with_capacity(input.block_header.len());
        for (i,value) in input.block_header.iter().enumerate() {
            let mut block_header = value.to_vec();
            let max_len = match network {
                Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
                Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
            };
            block_header.resize(max_len, 0);

            // It has been checked whether keccak(rlp(block_header)) is equal to block_hash.
            // Therefore, there is no need to declare the qualification repeatedly.
            let block_witness_temp = self.decompose_block_header_phase0(ctx, keccak, &block_header, network);
            // The parent hash of the current block
            let parent_hash_element = bytes_be_to_u128(ctx, self.gate(), &block_witness_temp.get("parent_hash").field_cells);

            let child_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness_temp.block_hash);


            // compute block number from big-endian bytes
            // let block_num_bytes = &block_witness.get("number").field_cells;
            // let block_num_len = block_witness.get("number").field_len;
            // let block_number =
            //     bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 4);
            // let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, 4);

            // verify block.parent_hash and local parent_hash
            if i!=0 {
                for (parent_hash_element, parent_hash) in parent_hash_element.iter().zip(parent_hash.iter()) {
                    ctx.constrain_equal(parent_hash_element, parent_hash);
                }
            }

            // Save the block hash of the current block as the parent hash
            parent_hash = child_hash.to_vec();

            block_witness.push(block_witness_temp);
        }



        let digest = EIP1186ResponseDigest {
            last_block_hash: parent_hash.try_into().unwrap(),
        };

        // parent_hash.clear();

        (EthTrackBlockTraceWitness { block_witness }, digest)
    }

    fn parse_track_block_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTrackBlockTraceWitness<F>,
    ) -> EthTrackBlockTrace<F>
        where
            Self: EthBlockHeaderChip<F> {
        let mut block_trace = Vec::with_capacity(witness.block_witness.len());
        for i in witness.block_witness {
            let block_witness = i;
            let block_trace_element = self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), block_witness);
            block_trace.push(block_trace_element);
        }

        EthTrackBlockTrace { block_trace }
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

impl EthTrackBlockInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTrackBlockInputAssigned {
        EthTrackBlockInputAssigned { block_header: self.block_header }
    }
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockInputAssigned {
    pub block_header: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct EthTrackBlockCircuit {
    pub inputs: EthTrackBlockInput,
    pub network: Network,
}

impl EthTrackBlockCircuit {
    pub fn from_provider(
        provider: &Provider<Http>,
        block_number_interval: Vec<u64>,
        network: Network,
    ) -> Self {
        use crate::providers::get_block_storage_track;

        let inputs = get_block_storage_track(
            provider,
            block_number_interval,
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
        let (witness, digest) = chip.parse_track_block_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input, self.network);

        let EIP1186ResponseDigest {
            last_block_hash,
        } = digest;

        let assigned_instances = last_block_hash
            .into_iter()
            .collect_vec();
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
                let _trace = chip.parse_track_block_proof_from_block_phase1(builder, witness);
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