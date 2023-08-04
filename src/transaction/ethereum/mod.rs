use std::{cell::RefCell};
use ethers_core::abi::AbiEncode;

use ethers_core::types::{Block, Bytes, H256};
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::utils::bit_length;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use lazy_static::lazy_static;
use zkevm_keccak::util::eth_types::Field;

use crate::{ETH_LOOKUP_BITS, EthChip, EthCircuitBuilder, EthPreCircuit, Network};
use crate::block_header::{BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace, EthBlockHeaderTraceWitness, get_block_header_config};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{MPTFixedKeyProof, MPTFixedKeyProofWitness, MPTUnFixedKeyInput};
use crate::providers::{ get_transaction_field_rlp, get_transaction_input};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldWitness};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{FIRST_PHASE, RlcContextPair, RlcTrace};
use crate::transaction::{EIP_1559_TX_TYPE_FIELDS_ITEM, EIP_1559_TX_TYPE_FIELDS_NUM, EIP_2718_TX_TYPE, EIP_2718_TX_TYPE_FIELDS_ITEM, EIP_2718_TX_TYPE_FIELDS_NUM, get_transaction_type};
use crate::util::helpers::{bytes_to_vec_u8, load_bytes};

pub mod tests;
pub mod helper;

// lazy_static! {
//     static ref KECCAK_RLP_EMPTY_STRING: Vec<u8> =
//         Vec::from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap();
// }

#[derive(Clone, Debug)]
pub struct EthTransactionInput {
    pub transaction_index: u32,
    pub transaction_proofs: MPTUnFixedKeyInput,
}

#[derive(Clone, Debug)]
pub struct EthTransactionInputAssigned<F: Field> {
    pub transaction_index: AssignedValue<F>,
    pub transaction_proofs: MPTFixedKeyProof<F>,
}

impl EthTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthTransactionInputAssigned<F> {
        let transaction_index = (F::from(self.transaction_index as u64)).try_into().unwrap();
        let transaction_index = ctx.load_witness(transaction_index);
        let transaction_proofs = self.transaction_proofs.assign(ctx);

        EthTransactionInputAssigned { transaction_index, transaction_proofs }
    }
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

#[derive(Clone, Debug)]
pub struct EthBlockTransactionInputAssigned<F: Field> {
    pub block_header: Vec<u8>,
    pub transaction: EthTransactionInputAssigned<F>,
}

impl EthBlockTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthBlockTransactionInputAssigned<F> {
        let transaction = self.transaction.assign(ctx);
        EthBlockTransactionInputAssigned { block_header: self.block_header, transaction }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionCircuit{
    pub inputs: EthBlockTransactionInput,
    pub block_header_config: BlockHeaderConfig,
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
        let inputs = get_transaction_input(
            provider,
            block_number,
            transaction_index,
            transaction_rlp,
            merkle_proof,
            transaction_pf_max_depth,
        );
        let block_header_config = get_block_header_config(&network);
        Self { inputs, block_header_config }
    }
}

impl EthPreCircuit for EthBlockTransactionCircuit {
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
        let (witness, digest) = chip.parse_transaction_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            &self.block_header_config);

        let EIP1186ResponseDigest {
            index,
            slots_values,
            transaction_is_empty
        } = digest;
        let assigned_instances = vec![index].into_iter()
            .chain(
                slots_values
            )
            .collect_vec();
        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            range.gate.assert_is_const(ctx, &transaction_is_empty, &Fr::zero());
        }

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
                let _trace = chip.parse_transaction_proof_from_block_phase1(builder, witness);
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub index: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<AssignedValue<F>>,
    pub transaction_is_empty: AssignedValue<F>,
}


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
    pub fn get_nonce(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[0]
    }
    pub fn get_gas_price(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[1]
    }
    pub fn get_gas_limit(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[2]
    }
    pub fn get_to(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[3]
    }
    pub fn get_value(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[4]
    }
    pub fn get_data(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[5]
    }
    pub fn get_v(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[6]
    }
    pub fn get_r(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[7]
    }
    pub fn get_s(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[8]
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockTransactionTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub transaction_witness: EthTransactionTraceWitness<F>,
}

pub trait EthBlockTransactionChip<F: Field> {

    // ================= FIRST PHASE ================

    fn parse_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTFixedKeyProof<F>,
    ) -> EthTransactionTraceWitness<F>;

    fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transactions_root: &[AssignedValue<F>],
        transaction_proofs: MPTFixedKeyProof<F>,
    ) -> EthTransactionTraceWitness<F>;


    // ================= SECOND PHASE ================

    fn parse_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockTransactionTraceWitness<F>,
    ) -> EthBlockTransactionTrace<F>
        where
            Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F>;

    fn parse_transaction_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthTransactionTraceWitness<F>,
    ) -> EthTransactionTrace<F>;
}

impl<'chip, F: Field> EthBlockTransactionChip<F> for EthChip<'chip, F> {

    // ================= FIRST PHASE ================

    fn parse_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockTransactionInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockTransactionTraceWitness<F>, EIP1186ResponseDigest<F>)
        where
            Self: EthBlockHeaderChip<F>, {

        let transaction_index = input.transaction.transaction_index;

        let block_witness = {
            let ctx = thread_pool.main(FIRST_PHASE);
            let mut block_header = input.block_header;
            block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);
            self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config)
        };
        let transactions_root = &block_witness.get_transactions_root().field_cells;

        // drop ctx
        let transaction_witness = self.parse_eip1186_proof_phase0(
            thread_pool,
            keccak,
            transactions_root,
            input.transaction.transaction_proofs,
        );
        let transaction_rlp = transaction_witness.mpt_witness.value_bytes.to_vec();

        let digest = EIP1186ResponseDigest {
            index: transaction_index,
            slots_values: transaction_rlp,
            transaction_is_empty: transaction_witness.mpt_witness.slot_is_empty,
        };
        (EthBlockTransactionTraceWitness { block_witness, transaction_witness }, digest)
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

    fn parse_transaction_proof_phase0(&self, ctx: &mut Context<F>, keccak: &mut KeccakChip<F>, transactions_root: &[AssignedValue<F>], transaction_proofs: MPTFixedKeyProof<F>) -> EthTransactionTraceWitness<F> {

        // check MPT root is transactions_root
        for (pf_root, root) in transaction_proofs.root_hash_bytes.iter().zip(transactions_root.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        let mut transaction_rlp_bytes;
        let mut fields_value_bytes = (vec![], vec![]);

        let type_value = transaction_proofs.value_bytes.first().unwrap();

        let test_value = self.gate().select(
            ctx,
            transaction_proofs.value_bytes[3],
            transaction_proofs.value_bytes[2],
            *type_value
        );
        println!("test_value:{:?}",test_value.value);

        let transaction_type = get_transaction_type(ctx, type_value);

        if transaction_type != EIP_2718_TX_TYPE {
            // Todo: Identify nested lists
            let non_prefix_bytes = transaction_proofs.value_bytes[1..].to_vec();
            let non_prefix_bytes_u8 = bytes_to_vec_u8(&non_prefix_bytes);

            fields_value_bytes = get_transaction_field_rlp(transaction_type, &non_prefix_bytes_u8, EIP_1559_TX_TYPE_FIELDS_NUM, EIP_1559_TX_TYPE_FIELDS_ITEM);
            transaction_rlp_bytes = load_bytes(ctx,&fields_value_bytes.0);
        } else {
            let non_prefix_bytes_u8 = bytes_to_vec_u8(&transaction_proofs.value_bytes);
            fields_value_bytes = get_transaction_field_rlp(transaction_type, &non_prefix_bytes_u8, EIP_2718_TX_TYPE_FIELDS_NUM, EIP_2718_TX_TYPE_FIELDS_ITEM);
            transaction_rlp_bytes = transaction_proofs.value_bytes.to_vec();
        }


        // let transaction_data_hash_query_id = keccak.keccak_fixed_len(
        //     ctx,
        //     &self.range().gate,
        //     vec![*transaction_rlp_bytes.get(5).unwrap()],
        //     Some(vec![])
        // );
        //
        // let transaction_data_hash = keccak.fixed_len_queries[transaction_data_hash_query_id].output_assigned.clone();
        // println!("transaction_data_hash:{:?}",transaction_data_hash);

        // parse EIP 2718 [nonce,gasPrice,gasLimit,to,value,data,v,r,s]
        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            transaction_rlp_bytes,
            &[32, 32, 32, 20, 32, 0, 32, 32, 32],//Maximum number of bytes per field. For example, the uint256 is 32 bytes.
            false,
        );

        // println!("len:{:?}",array_witness.field_witness.len());

        assert_eq!(array_witness.field_witness.len(),EIP_2718_TX_TYPE_FIELDS_NUM);

        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, transaction_proofs);

        EthTransactionTraceWitness { array_witness, mpt_witness }
    }


    // ================= SECOND PHASE ================

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
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), 12);

        transaction_trace
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
}







