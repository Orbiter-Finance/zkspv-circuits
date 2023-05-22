use std::{cell::RefCell, env::var};

use ethers_core::types::{BlockId, Bytes};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::RangeChip;
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, Network};
use crate::arbitrum_block_header::EthBlockHeaderChip;
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::providers::get_arbitrum_proof;
use crate::receipt::{EthBlockReceiptChip, EthBlockReceiptInput, EthBlockReceiptInputAssigned, EthBlockReceiptTrace, EthBlockReceiptTraceWitness};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::FIRST_PHASE;
use crate::rlp::RlpChip;
use crate::track_block::{EthTrackBlockChip, EthTrackBlockInput, EthTrackBlockInputAssigned, EthTrackBlockTrace, EthTrackBlockTraceWitness};
use crate::transaction::ethereum::{EthBlockTransactionChip, EthBlockTransactionInput, EthBlockTransactionInputAssigned, EthBlockTransactionTrace, EthBlockTransactionTraceWitness};
use crate::util::{AssignedH256, EthConfigParams};

mod tests;

#[derive(Clone, Debug)]
pub struct ArbitrumProofInput {
    pub l2_seq_num: u64,
    pub arbitrum_transaction_status: EthBlockTransactionInput,
    pub arbitrum_receipt_status: EthBlockReceiptInput,
    pub arbitrum_block_status: EthTrackBlockInput,
    pub ethereum_transaction_status: EthBlockTransactionInput,
    pub ethereum_block_status: EthTrackBlockInput,
}

#[derive(Clone, Debug)]
pub struct ArbitrumProofInputAssigned<F: Field> {
    pub l2_seq_num: AssignedValue<F>,
    pub arbitrum_transaction_status: EthBlockTransactionInputAssigned<F>,
    pub arbitrum_receipt_status: EthBlockReceiptInputAssigned<F>,
    pub arbitrum_block_status: EthTrackBlockInputAssigned,
    pub ethereum_transaction_status: EthBlockTransactionInputAssigned<F>,
    pub ethereum_block_status: EthTrackBlockInputAssigned,
}

impl ArbitrumProofInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ArbitrumProofInputAssigned<F> {
        let l2_seq_num = (F::from(self.l2_seq_num as u64)).try_into().unwrap();
        let l2_seq_num = ctx.load_witness(l2_seq_num);
        let arbitrum_transaction_status = self.arbitrum_transaction_status.assign(ctx);
        let arbitrum_receipt_status = self.arbitrum_receipt_status.assign(ctx);
        let arbitrum_block_status = self.arbitrum_block_status.assign(ctx);
        let ethereum_transaction_status = self.ethereum_transaction_status.assign(ctx);
        let ethereum_block_status = self.ethereum_block_status.assign(ctx);
        ArbitrumProofInputAssigned {
            l2_seq_num,
            arbitrum_transaction_status,
            arbitrum_receipt_status,
            arbitrum_block_status,
            ethereum_transaction_status,
            ethereum_block_status,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArbitrumProofTransactionOrReceipt {
    pub index: u32,
    pub rlp: Vec<u8>,
    pub merkle_proof: Vec<Bytes>,
    pub pf_max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct ArbitrumProofBlockTrack {
    pub start_block: u32,
    pub end_block: BlockId,
}


#[derive(Clone, Debug)]
pub struct ArbitrumProofCircuit {
    pub inputs: ArbitrumProofInput,
    pub arbitrum_network: Network,
    pub ethereum_network: Network,
}

impl ArbitrumProofCircuit {
    pub fn from_provider(
        arbitrum_provider: &Provider<Http>,
        ethereum_provider: &Provider<Http>,
        l2_seq_num: u64,
        transaction_or_receipt: Vec<ArbitrumProofTransactionOrReceipt>,
        trace_blocks: Vec<ArbitrumProofBlockTrack>,
        arbitrum_network: Network,
        ethereum_network: Network,
    ) -> Self {
        let inputs = get_arbitrum_proof(
            arbitrum_provider,
            ethereum_provider,
            l2_seq_num,
            transaction_or_receipt,
            trace_blocks,
        );
        Self { inputs, arbitrum_network, ethereum_network }
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

        let (witness, digest) = chip.parse_arbitrum_proof_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input, self.arbitrum_network, self.ethereum_network);

        let EIP1186ResponseDigest {
            arbitrum_tx,
            seq_number,
            arbitrum_block_end_hash,
            ethereum_block_end_hash
        } = digest;//arbitrum_tx

        let assigned_instances = arbitrum_tx
            .into_iter()
            .chain([seq_number])
            .chain(
                arbitrum_block_end_hash
            ).chain(ethereum_block_end_hash)
            .collect_vec();
        // {
        //     let ctx = builder.gate_builder.main(FIRST_PHASE);
        //     range.gate.assert_is_const(ctx, &receipt_is_empty, &F::zero());
        // }

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
                let _trace = chip.parse_arbitrum_proof_phase1(builder, witness);
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
    pub arbitrum_tx: Vec<AssignedValue<F>>,
    pub seq_number: AssignedValue<F>,
    pub arbitrum_block_end_hash: AssignedH256<F>,
    pub ethereum_block_end_hash: AssignedH256<F>,
}

#[derive(Clone, Debug)]
pub struct ArbitrumProofTrace<F: Field> {
    pub arbitrum_transaction_trace: EthBlockTransactionTrace<F>,
    pub arbitrum_receipt_trace: EthBlockReceiptTrace<F>,
    pub arbitrum_block_trace: EthTrackBlockTrace<F>,
    pub ethereum_transaction_trace: EthBlockTransactionTrace<F>,
    pub ethereum_block_trace: EthTrackBlockTrace<F>,
}


#[derive(Clone, Debug)]
pub struct ArbitrumProofTraceWitness<F: Field> {
    pub arbitrum_transaction_witness: EthBlockTransactionTraceWitness<F>,
    pub arbitrum_receipt_witness: EthBlockReceiptTraceWitness<F>,
    pub arbitrum_block_witness: EthTrackBlockTraceWitness<F>,
    pub ethereum_transaction_witness: EthBlockTransactionTraceWitness<F>,
    pub ethereum_block_witness: EthTrackBlockTraceWitness<F>,
}

pub trait ArbitrumProofChip<F: Field> {

    // ================= FIRST PHASE ================

    fn parse_arbitrum_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ArbitrumProofInputAssigned<F>,
        arbitrum_network: Network,
        ethereum_network: Network,
    ) -> (ArbitrumProofTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>;


    // ================= SECOND PHASE ================

    fn parse_arbitrum_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ArbitrumProofTraceWitness<F>,
    ) -> ArbitrumProofTrace<F>
        where
            Self: EthBlockHeaderChip<F>;
}

impl<'chip, F: Field> ArbitrumProofChip<F> for EthChip<'chip, F> {
    fn parse_arbitrum_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ArbitrumProofInputAssigned<F>,
        arbitrum_network: Network,
        ethereum_network: Network,
    ) -> (ArbitrumProofTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F> {
        let (arbitrum_transaction_witness, arbitrum_transaction_digest) = self.parse_transaction_proof_from_block_phase0(
            thread_pool,
            keccak,
            input.arbitrum_transaction_status, arbitrum_network);

        let (arbitrum_receipt_witness, _) = self.parse_receipt_proof_from_block_phase0(
            thread_pool,
            keccak,
            input.arbitrum_receipt_status, arbitrum_network);

        let (arbitrum_block_witness, arbitrum_block_digest) = self.parse_track_block_proof_from_block_phase0(
            thread_pool,
            keccak,
            input.arbitrum_block_status, arbitrum_network);

        let (ethereum_transaction_witness, _) = self.parse_transaction_proof_from_block_phase0(
            thread_pool,
            keccak,
            input.ethereum_transaction_status, ethereum_network);

        let (ethereum_block_witness, ethereum_block_digest) = self.parse_track_block_proof_from_block_phase0(
            thread_pool,
            keccak,
            input.ethereum_block_status, ethereum_network);

        let digest = EIP1186ResponseDigest {
            arbitrum_tx: arbitrum_transaction_digest.slots_values,
            seq_number: input.l2_seq_num,
            arbitrum_block_end_hash: arbitrum_block_digest.last_block_hash,
            ethereum_block_end_hash: ethereum_block_digest.last_block_hash,
        };

        (ArbitrumProofTraceWitness {
            arbitrum_transaction_witness,
            arbitrum_receipt_witness,
            arbitrum_block_witness,
            ethereum_transaction_witness,
            ethereum_block_witness,
        }, digest)
    }


    // ================= SECOND PHASE ================

    fn parse_arbitrum_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ArbitrumProofTraceWitness<F>,
    ) -> ArbitrumProofTrace<F>
        where
            Self: EthBlockHeaderChip<F> {
        let arbitrum_transaction_trace = self.parse_transaction_proof_from_block_phase1(thread_pool, witness.arbitrum_transaction_witness);
        let arbitrum_receipt_trace = self.parse_receipt_proof_from_block_phase1(thread_pool, witness.arbitrum_receipt_witness);
        let arbitrum_block_trace = self.parse_track_block_proof_from_block_phase1(thread_pool, witness.arbitrum_block_witness);
        let ethereum_transaction_trace = self.parse_transaction_proof_from_block_phase1(thread_pool, witness.ethereum_transaction_witness);
        let ethereum_block_trace = self.parse_track_block_proof_from_block_phase1(thread_pool, witness.ethereum_block_witness);

        ArbitrumProofTrace {
            arbitrum_transaction_trace,
            arbitrum_receipt_trace,
            arbitrum_block_trace,
            ethereum_transaction_trace,
            ethereum_block_trace,
        }
    }
}