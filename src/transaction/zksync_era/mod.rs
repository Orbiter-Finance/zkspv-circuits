use crate::block_header::zksync_era::{
    ZkSyncEraBlockHeaderChip, ZkSyncEraBlockHeaderInput, ZkSyncEraBlockHeaderInputAssigned,
    ZkSyncEraBlockHeaderTrace, ZkSyncEraBlockHeaderTraceWitness,
};
use crate::ecdsa::{EcdsaChip, EthEcdsaInput, EthEcdsaInputAssigned};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{AssignedBytes, MPTProofWitness};
use crate::providers::get_zksync_era_transaction_input;
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{RlcContextPair, FIRST_PHASE};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace};
use crate::storage::EthStorageChip;
use crate::transaction::ethereum::{
    EthBlockTransactionChip, EthTransactionExtraWitness, EthTransactionField,
};

use crate::receipt::TX_STATUS_SUCCESS;
use crate::transaction::util::TransactionConstructor;
use crate::util::helpers::{bytes_to_u8, bytes_to_vec_u8, load_bytes};
use crate::util::{
    bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, u128s_to_bytes_be, AssignedH256,
};
use crate::{
    EthChip, EthCircuitBuilder, EthPreCircuit, ETH_LIMB_BITS, ETH_LOOKUP_BITS, ETH_NUM_LIMBS,
};
use ethers_core::types::{Block, H256};
use ethers_providers::{Http, Provider};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::{AssignedValue, Context};
use itertools::Itertools;
use snark_verifier::loader::halo2::halo2_ecc::secp256k1::{FpChip, FqChip};
use std::cell::RefCell;
use zkevm_keccak::util::eth_types::Field;
use zksync_web3_rs::zks_provider::types::BlockDetails;

mod tests;

const CACHE_BITS: usize = 12;

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionInput {
    pub transaction_index: u64,
    pub transaction_status: u64,
    pub transaction_value: Vec<u8>,
    pub transaction_value_max_bytes: usize,
    pub transaction_ecdsa_verify: EthEcdsaInput,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionInputAssigned<F: Field> {
    pub transaction_index: AssignedValue<F>,
    pub transaction_status: AssignedValue<F>,
    pub transaction_value: AssignedBytes<F>,
    pub transaction_value_max_bytes: AssignedValue<F>,
    pub transaction_ecdsa_verify: EthEcdsaInputAssigned<F>,
}

impl ZkSyncEraTransactionInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ZkSyncEraTransactionInputAssigned<F> {
        let Self { mut transaction_value, .. } = self;
        let transaction_index = ctx.load_witness(F::from(self.transaction_index));
        let transaction_status = ctx.load_witness(F::from(self.transaction_status));
        let transaction_value_max_bytes =
            ctx.load_witness(F::from(self.transaction_value_max_bytes as u64));
        transaction_value.resize(self.transaction_value_max_bytes, 0);
        let transaction_value = load_bytes(ctx, transaction_value.as_slice());
        let transaction_ecdsa_verify = self.transaction_ecdsa_verify.assign(ctx);
        ZkSyncEraTransactionInputAssigned {
            transaction_index,
            transaction_status,
            transaction_value,
            transaction_value_max_bytes,
            transaction_ecdsa_verify,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockTransactionInput {
    pub block_header: ZkSyncEraBlockHeaderInput,
    pub transaction: ZkSyncEraTransactionInput,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockTransactionInputAssigned<F: Field> {
    pub block_header: ZkSyncEraBlockHeaderInputAssigned<F>,
    pub transaction: ZkSyncEraTransactionInputAssigned<F>,
}

impl ZkSyncEraBlockTransactionInput {
    pub fn assign<F: Field>(
        self,
        ctx: &mut Context<F>,
    ) -> ZkSyncEraBlockTransactionInputAssigned<F> {
        let block_header = self.block_header.assign(ctx);
        let transaction = self.transaction.assign(ctx);
        ZkSyncEraBlockTransactionInputAssigned { block_header, transaction }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockTransactionCircuit {
    pub inputs: ZkSyncEraBlockTransactionInput,
}

impl ZkSyncEraBlockTransactionCircuit {
    pub fn from_provider(provider: &Provider<Http>, constructor: TransactionConstructor) -> Self {
        let inputs = get_zksync_era_transaction_input(provider, constructor.transaction_hash);
        Self { inputs }
    }
}

impl EthPreCircuit for ZkSyncEraBlockTransactionCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let chip = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();
        let fp_chip = FpChip::new(&range, ETH_LIMB_BITS, ETH_NUM_LIMBS);
        let fq_chip = FqChip::new(&range, ETH_LIMB_BITS, ETH_NUM_LIMBS);
        let ecdsa = EcdsaChip::new(&fp_chip, &fq_chip);

        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let input = self.inputs.assign(ctx);

        let (witness, digest) = chip.parse_zksync_era_transaction_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            &ecdsa,
            input,
        );

        let ZkSyncEraTransactionDigest { index, block_hash, transaction_field } = digest;
        println!("chain_id:{:?}", transaction_field.chain_id);
        println!("hash:{:?}", transaction_field.hash);
        println!("from:{:?}", transaction_field.from);
        println!("to:{:?}", transaction_field.to);
        println!("token:{:?}", transaction_field.token);
        println!("amount:{:?}", transaction_field.amount);
        println!("nonce:{:?}", transaction_field.nonce);
        println!("time_stamp:{:?}", transaction_field.time_stamp);

        let assigned_instances = block_hash
            .into_iter()
            .chain(transaction_field.hash)
            .chain([
                transaction_field.chain_id,
                index,
                transaction_field.from,
                transaction_field.to,
                transaction_field.token,
                transaction_field.amount,
                transaction_field.nonce,
                transaction_field.time_stamp,
                transaction_field.dest_transfer_address,
                transaction_field.dest_transfer_token,
            ])
            .collect_vec();

        // {
        //     let ctx = builder.gate_builder.main(FIRST_PHASE);
        //     range.gate.assert_is_const(ctx, &transaction_is_empty, &Fr::zero());
        // }

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
                let _trace =
                    chip.parse_zksync_era_transaction_proof_from_block_phase1(builder, witness);
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionDigest<F: Field> {
    pub index: AssignedValue<F>,
    pub block_hash: AssignedH256<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub transaction_field: EthTransactionField<F>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionTrace<F: Field> {
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockTransactionTrace<F: Field> {
    pub block_trace: ZkSyncEraBlockHeaderTrace<F>,
    pub transaction_trace: ZkSyncEraTransactionTrace<F>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraTransactionTraceWitness<F: Field> {
    transaction_witness: RlpArrayTraceWitness<F>,
    extra_witness: EthTransactionExtraWitness<F>,
}

#[derive(Clone, Debug)]
pub struct ZkSyncEraBlockTransactionTraceWitness<F: Field> {
    pub block_witness: ZkSyncEraBlockHeaderTraceWitness<F>,
    pub transaction_witness: ZkSyncEraTransactionTraceWitness<F>,
}

pub trait ZkSyncEraBlockTransactionChip<F: Field> {
    fn parse_zksync_era_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        ecdsa: &EcdsaChip<F>,
        input: ZkSyncEraBlockTransactionInputAssigned<F>,
    ) -> (ZkSyncEraBlockTransactionTraceWitness<F>, ZkSyncEraTransactionDigest<F>)
    where
        Self: ZkSyncEraBlockHeaderChip<F>;

    fn parse_zksync_era_transaction_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        ecdsa: &EcdsaChip<F>,
        transaction_input: ZkSyncEraTransactionInputAssigned<F>,
        block_txs: Vec<AssignedBytes<F>>,
    ) -> ZkSyncEraTransactionTraceWitness<F>
    where
        Self: EthBlockTransactionChip<F>;

    fn parse_zksync_era_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncEraBlockTransactionTraceWitness<F>,
    ) -> ZkSyncEraBlockTransactionTrace<F>
    where
        Self: ZkSyncEraBlockHeaderChip<F>;

    fn parse_zksync_era_transaction_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncEraTransactionTraceWitness<F>,
    ) -> ZkSyncEraTransactionTrace<F>;
}

impl<'chip, F: Field> ZkSyncEraBlockTransactionChip<F> for EthChip<'chip, F> {
    fn parse_zksync_era_transaction_proof_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        ecdsa: &EcdsaChip<F>,
        input: ZkSyncEraBlockTransactionInputAssigned<F>,
    ) -> (ZkSyncEraBlockTransactionTraceWitness<F>, ZkSyncEraTransactionDigest<F>)
    where
        Self: ZkSyncEraBlockHeaderChip<F>,
    {
        let transaction_index = input.transaction.transaction_index;

        let block_witness = {
            let ctx = thread_pool.main(FIRST_PHASE);
            self.decompose_block_header_phase0(ctx, keccak, input.block_header)
        };
        let ctx = thread_pool.main(FIRST_PHASE);
        let block_hash = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        let time_stamp = self.rlp_field_witnesses_to_uint(
            ctx,
            vec![&block_witness.rlp_witness.get_timestamp()],
            vec![8],
        )[0]
        .clone();

        let transaction_witness = self.parse_zksync_era_transaction_proof_phase0(
            thread_pool,
            keccak,
            ecdsa,
            input.transaction.clone(),
            block_witness.txs_hash.clone(),
        );

        let digest = ZkSyncEraTransactionDigest {
            index: transaction_index,
            block_hash: block_hash.try_into().unwrap(),
            transaction_field: EthTransactionField {
                hash: transaction_witness.extra_witness.hash,
                chain_id: transaction_witness.extra_witness.chain_id,
                from: transaction_witness.extra_witness.from,
                to: transaction_witness.extra_witness.to,
                token: transaction_witness.extra_witness.token,
                amount: transaction_witness.extra_witness.amount,
                nonce: transaction_witness.extra_witness.nonce,
                time_stamp,
                dest_transfer_address: transaction_witness.extra_witness.dest_transfer_address,
                dest_transfer_token: transaction_witness.extra_witness.dest_transfer_token,
            },
        };
        (ZkSyncEraBlockTransactionTraceWitness { block_witness, transaction_witness }, digest)
    }

    fn parse_zksync_era_transaction_proof_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        ecdsa: &EcdsaChip<F>,
        transaction_input: ZkSyncEraTransactionInputAssigned<F>,
        block_txs: Vec<AssignedBytes<F>>,
    ) -> ZkSyncEraTransactionTraceWitness<F>
    where
        Self: EthBlockTransactionChip<F>,
    {
        let ctx = thread_pool.main(FIRST_PHASE);

        let (transaction_witness, transaction_extra_witness) = self.parse_transaction_extra_proof(
            ctx,
            keccak,
            ecdsa,
            transaction_input.transaction_value,
            transaction_input.transaction_ecdsa_verify,
        );

        let target_tx_hash_in_block =
            block_txs.get(bytes_to_u8(&transaction_input.transaction_index) as usize).unwrap();
        let target_tx_hash_in_block =
            load_bytes(ctx, bytes_to_vec_u8(target_tx_hash_in_block).as_slice());
        let hash = u128s_to_bytes_be(ctx, self.range(), &transaction_extra_witness.hash);
        for (target_tx_hash, hash) in target_tx_hash_in_block.iter().zip(hash.iter()) {
            ctx.constrain_equal(target_tx_hash, hash);
        }

        let tx_status_success = ctx.load_witness(F::from(TX_STATUS_SUCCESS as u64));

        ctx.constrain_equal(&transaction_input.transaction_status, &tx_status_success);

        ZkSyncEraTransactionTraceWitness {
            transaction_witness,
            extra_witness: transaction_extra_witness,
        }
    }

    fn parse_zksync_era_transaction_proof_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncEraBlockTransactionTraceWitness<F>,
    ) -> ZkSyncEraBlockTransactionTrace<F>
    where
        Self: ZkSyncEraBlockHeaderChip<F>,
    {
        let block_trace =
            self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let transaction_trace = self
            .parse_zksync_era_transaction_proof_phase1(thread_pool, witness.transaction_witness);
        ZkSyncEraBlockTransactionTrace { block_trace, transaction_trace }
    }

    fn parse_zksync_era_transaction_proof_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ZkSyncEraTransactionTraceWitness<F>,
    ) -> ZkSyncEraTransactionTrace<F> {
        // self.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);
        let value_trace = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.transaction_witness, true)
            .field_trace
            .try_into()
            .unwrap();
        ZkSyncEraTransactionTrace { value_trace }
    }
}
