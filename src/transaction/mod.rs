use std::{cell::RefCell, env::var};

use ethers_core::types::{Block, Bytes, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::utils::bit_length;
use itertools::Itertools;
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, Network};
use crate::block_header::{EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness, GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{ MPTFixedKeyProof, MPTFixedKeyProofWitness, MPTUnFixedKeyInput};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldWitness};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{FIRST_PHASE, RlcContextPair, RlcTrace};
use crate::util::{AssignedH256, bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, EthConfigParams};

mod tests;

#[derive(Clone, Debug)]
pub struct EthTransactionTrace<F: Field> {
    pub nonce_trace: RlcTrace<F>,
    pub gas_price_trace: RlcTrace<F>,
    pub gas_limit_trace: RlcTrace<F>,
    pub to_trace: RlcTrace<F>,
    pub value_trace: RlcTrace<F>,
    pub data_trace: RlcTrace<F>,
    pub v_trace: RlcTrace<F>,
    pub r_trace: RlcTrace<F>,
    pub s_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub transaction_trace: EthTransactionTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthTransactionTraceWitness<F: Field> {
    array_witness: RlpArrayTraceWitness<F>,
    mpt_witness: MPTFixedKeyProofWitness<F>,
}

impl<F: Field> EthTransactionTraceWitness<F> {
    pub fn get(&self, transaction_field: &str) -> &RlpFieldWitness<F> {
        match transaction_field {
            "nonce" => &self.array_witness.field_witness[0],
            "gasPrice" => &self.array_witness.field_witness[1],
            "gasLimit" => &self.array_witness.field_witness[2],
            "to" => &self.array_witness.field_witness[3],
            "value" => &self.array_witness.field_witness[4],
            "data" => &self.array_witness.field_witness[5],
            "v" => &self.array_witness.field_witness[6],
            "r" => &self.array_witness.field_witness[7],
            "s" => &self.array_witness.field_witness[8],
            _ => panic!("invalid EIP-2718 transaction field"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub transaction_witness: EthTransactionTraceWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub index: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<AssignedValue<F>>,
    pub transaction_is_empty: AssignedValue<F>,
}

pub trait EthBlockTransactionChip<F: Field> {
    fn parse_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        network: Network,
    ) -> (EthBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>;
    fn parse_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F>
        where
            Self: EthBlockHeaderChip<F>;
    fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTFixedKeyProof<F>,
    ) -> EthTransactionTraceWitness<F>;

    fn parse_transaction_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F>;

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTFixedKeyProof<F>,
    ) -> EthTransactionTraceWitness<F>;

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F>;
}

impl<'chip, F: Field> EthBlockTransactionChip<F> for EthChip<'chip, F> {
    fn parse_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        network: Network,
    ) -> (EthBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>, {
        let ctx = thread_pool.main(FIRST_PHASE);
        let transaction_index = input.transaction.transaction_index;
        let mut block_header = input.block_header;
        let max_len = match network {
            Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
        };
        block_header.resize(max_len, 0);
        let block_witness = self.decompose_block_header_phase0(ctx, keccak, &block_header, network);
        let transactions_root = &block_witness.get("transactions_root").field_cells;
        let block_hash_hi_lo = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.get("number").field_cells;
        let block_num_len = block_witness.get("number").field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 4);
        let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, 4);

        // drop ctx
        let transaction_witness = self.parse_eip1186_proof_phase0(
            thread_pool,
            keccak,
            transactions_root,
            input.transaction.transaction_proofs,
        );
        let transaction_rlp = transaction_witness.mpt_witness.value_bytes.to_vec();

        let digest = EIP1186ResponseDigest {
            block_hash: block_hash_hi_lo.try_into().unwrap(),
            block_number,
            index: transaction_index,
            slots_values: transaction_rlp,
            transaction_is_empty: transaction_witness.mpt_witness.slot_is_empty,
        };
        (EthBlockTransactionTraceWitness { block_witness, transaction_witness }, digest)
    }

    fn parse_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F>
        where
            Self: EthBlockHeaderChip<F> {
        let block_trace = self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let transaction_trace = self.parse_eip1186_proof_phase1(thread_pool, witness.transaction_witness);
        EthBlockTransactionTrace { block_trace, transaction_trace }
    }

    fn parse_transaction_proof_phase0(&self, ctx: &mut Context<F>, keccak: &mut KeccakChip<F>, transactions_root: &[AssignedValue<F>], transaction_proofs: MPTFixedKeyProof<F>) -> EthTransactionTraceWitness<F> {

        // check MPT root is transactions_root
        for (pf_root, root) in transaction_proofs.root_hash_bytes.iter().zip(transactions_root.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse EIP 2718 [nonce,gasPrice,gasLimit,to,value,data,v,r,s]
        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            transaction_proofs.value_bytes.clone(),
            &[32, 32, 32, 20, 32, 100000, 32, 32, 32],//Maximum number of bytes per field. For example, the uint256 is 32 bytes.
            false,
        );

        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, transaction_proofs);

        EthTransactionTraceWitness { array_witness, mpt_witness }
    }

    fn parse_transaction_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F> {
        self.parse_mpt_inclusion_fixed_key_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        let array_trace: [_; 9] = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.array_witness, false)
            .field_trace
            .try_into()
            .unwrap();
        let [
        nonce_trace,
        gas_price_trace,
        gas_limit_trace,
        to_trace,
        value_trace,
        data_trace,
        v_trace,
        r_trace,
        s_trace
        ] =
            array_trace.map(|trace| trace.field_trace);
        EthTransactionTrace {
            nonce_trace,
            gas_price_trace,
            gas_limit_trace,
            to_trace,
            value_trace,
            data_trace,
            v_trace,
            r_trace,
            s_trace,
        }
    }


    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTFixedKeyProof<F>,
    ) -> EthTransactionTraceWitness<F> {
        let ctx = thread_pool.main(FIRST_PHASE);
        let transaction_trace = self.parse_transaction_proof_phase0(
            ctx,
            keccak,
            transactions_root,
            transaction_proofs,
        );
        transaction_trace
    }

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F> {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let copy_witness = &witness.clone();
        let transaction_trace = self.parse_transaction_proof_phase1((ctx_gate, ctx_rlc), witness);

        let max_len = (2 * &copy_witness.mpt_witness.key_byte_len).max(copy_witness.array_witness.rlp_array.len());
        let cache_bits = bit_length(max_len as u64);
        // let ctxs: Vec<(Context<F>, Context<F>)> = vec![*(t1, a1)];
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), cache_bits);


        // let (mut ctxs_gate, mut ctxs_rlc): (Vec<_>, Vec<_>) = ctxs.into_iter().unzip();
        // thread_pool.gate_builder.threads[RLC_PHASE].append(&mut ctxs_gate);
        // thread_pool.threads_rlc.append(&mut ctxs_rlc);
        transaction_trace
    }
}


#[derive(Clone, Debug)]
pub struct EthTransactionInput {
    pub transaction_index: u32,
    pub transaction_proofs: MPTUnFixedKeyInput, // key proof
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionInput {
    pub block: Block<H256>,
    pub block_number: u32,
    pub block_hash: H256,
    // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub transaction: EthTransactionInput,
}

impl EthTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTransactionInputAssigned<F> {
        let transaction_index = (F::from(self.transaction_index as u64)).try_into().unwrap();
        let transaction_index = ctx.load_witness(transaction_index);
        let transaction_proofs = self.transaction_proofs.assign(ctx);

        EthTransactionInputAssigned { transaction_index, transaction_proofs }
    }
}

impl EthBlockTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthBlockTransactionInputAssigned<F> {
        let transaction = self.transaction.assign(ctx);
        EthBlockTransactionInputAssigned { block_header: self.block_header, transaction }
    }
}

#[derive(Clone, Debug)]
pub struct EthTransactionInputAssigned<F: Field> {
    pub transaction_index: AssignedValue<F>,
    pub transaction_proofs: MPTFixedKeyProof<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionInputAssigned<F: Field> {
    pub block_header: Vec<u8>,
    pub transaction: EthTransactionInputAssigned<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionCircuit {
    pub inputs: EthBlockTransactionInput,
    pub network: Network,
}

impl EthBlockTransactionCircuit {
    pub fn from_provider(
        provider: &Provider<Http>,
        block_number: u32,
        transaction_index: u32,
        transaction_rlp: Vec<u8>,
        merkle_proof: Vec<Bytes>,
        transaction_pf_max_depth: usize,
        network: Network,
    ) -> Self {
        use crate::providers::get_block_storage_input_transaction;

        let inputs = get_block_storage_input_transaction(
            provider,
            block_number,
            transaction_index,
            transaction_rlp,
            merkle_proof,
            transaction_pf_max_depth,
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
        let (witness, digest) = chip.parse_transaction_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input, self.network);

        let EIP1186ResponseDigest {
            block_hash,
            block_number,
            index,
            slots_values,
            transaction_is_empty
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
            range.gate.assert_is_const(ctx, &transaction_is_empty, &F::zero());
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
                let _trace = chip.parse_transaction_proof_from_block_phase1(builder, witness);
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