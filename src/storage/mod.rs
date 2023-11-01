use std::io::Read;
use std::{cell::RefCell, env::var, fs::File, path::Path};

use ethers_core::types::{Address, Block, H256, U256};
#[cfg(feature = "providers")]
use ethers_providers::{Http, Provider};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions, RangeChip},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};
use itertools::Itertools;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::block_header::{
    get_block_header_config, BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace,
    EthBlockHeaderTraceWitness,
};
use crate::keccak::{parallelize_keccak_phase0, ContainsParallelizableKeccakQueries};
use crate::mpt::{MPTInput, MPTProof, MPTProofWitness};
use crate::providers::get_storage_input;
use crate::rlp::builder::parallelize_phase1;
use crate::rlp::RlpFieldTrace;
use crate::storage::util::StorageConstructor;
use crate::{
    keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs},
    mpt::AssignedBytes,
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::{RlcContextPair, RlcTrace, FIRST_PHASE, RLC_PHASE},
        RlpArrayTraceWitness, RlpChip, RlpFieldTraceWitness, RlpFieldWitness,
    },
    util::{
        bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, encode_addr_to_field,
        encode_h256_to_field, encode_u256_to_field, uint_to_bytes_be, AssignedH256,
        EthConfigParams,
    },
    EthChip, EthCircuitBuilder, EthPreCircuit, Field, Network, ETH_LOOKUP_BITS,
};

// #[cfg(all(test, feature = "providers"))]
pub mod helper;
pub mod tests;
pub mod util;
const CACHE_BITS: usize = 10;
const EBC_RULE_FIELDS_NUM: usize = 18;
const EBC_RULE_FIELDS_MAX_FIELDS_LEN: [usize; EBC_RULE_FIELDS_NUM] =
    [8, 8, 1, 1, 32, 32, 16, 16, 16, 16, 16, 16, 4, 4, 4, 4, 4, 4];

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfigParams {
    pub degree: u32,
    // number of SecondPhase advice columns used in RlcConfig
    pub num_rlc_columns: usize,
    // the number of advice columns in phase _ without lookup enabled that RangeConfig uses
    pub num_range_advice: Vec<usize>,
    // the number of advice columns in phase _ with lookup enabled that RangeConfig uses
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    // for keccak chip you should know the number of unusable rows beforehand
    pub unusable_rows: usize,
    pub keccak_rows_per_round: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_bits: Option<usize>,
}

impl StorageConfigParams {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        serde_json::from_reader(File::open(&path).expect("path does not exist")).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct EthAccountTrace<F: Field> {
    pub nonce_trace: RlcTrace<F>,
    pub balance_trace: RlcTrace<F>,
    pub storage_root_trace: RlcTrace<F>,
    pub code_hash_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthAccountTraceWitness<F: Field> {
    array_witness: RlpArrayTraceWitness<F>,
    mpt_witness: MPTProofWitness<F>,
}

impl<F: Field> EthAccountTraceWitness<F> {
    pub fn get_nonce(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[0]
    }
    pub fn get_balance(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[1]
    }
    pub fn get_storage_root(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[2]
    }
    pub fn get_code_hash(&self) -> &RlpFieldWitness<F> {
        &self.array_witness.field_witness[3]
    }
}

#[derive(Clone, Debug)]
pub struct EthStorageTrace<F: Field> {
    pub value_trace: RlcTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthStorageTraceWitness<F: Field> {
    value_witness: RlpFieldTraceWitness<F>,
    mpt_witness: MPTProofWitness<F>,
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthStorageTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

impl<F: Field> ContainsParallelizableKeccakQueries for EthAccountTraceWitness<F> {
    fn shift_query_indices(&mut self, fixed_shift: usize, var_shift: usize) {
        self.mpt_witness.shift_query_indices(fixed_shift, var_shift);
    }
}

#[derive(Clone, Debug)]
pub struct EthEbcRuleTrace<F: Field> {
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct EthEbcRuleTraceWitness<F: Field> {
    ebc_rule_rlp_witness: RlpArrayTraceWitness<F>,
    ebc_rule_mpt_witness: MPTProofWitness<F>,
}

// parse value RLP([
// chain_id0,chain_id1,
// status0,status1,
// token0,token1,
// min_price0,min_price1,
// max_price0,max_price1,
// with_holding_fee0,with_holding_fee1,
// trading_fee0,trading_fee1,
// response_time0,response_time1,
// compensation_ratio0,compensation_ratio1])
impl<F: Field> EthEbcRuleTraceWitness<F> {
    pub fn get_source_chain_id(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[0]
    }
    pub fn get_source_status(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[2]
    }
    pub fn get_source_token(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[4]
    }
    pub fn get_source_min_price(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[6]
    }
    pub fn get_source_max_price(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[8]
    }
    pub fn get_source_with_holding_fee(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[10]
    }
    pub fn get_source_trading_fee(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[12]
    }
    pub fn get_source_response_time(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[14]
    }
    pub fn get_source_compensation_ratio(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[16]
    }

    pub fn get_dest_chain_id(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[1]
    }
    pub fn get_dest_status(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[3]
    }
    pub fn get_dest_token(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[5]
    }
    pub fn get_dest_min_price(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[7]
    }
    pub fn get_dest_max_price(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[9]
    }
    pub fn get_dest_with_holding_fee(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[11]
    }
    pub fn get_dest_trading_fee(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[13]
    }
    pub fn get_dest_response_time(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[15]
    }
    pub fn get_dest_compensation_ratio(&self) -> &RlpFieldWitness<F> {
        &self.ebc_rule_rlp_witness.field_witness[17]
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub acct_trace: EthAccountTrace<F>,
    pub storage_trace: Vec<EthStorageTrace<F>>,
    pub ebc_rule_trace: EthEbcRuleTrace<F>,
}

#[derive(Clone, Debug)]
pub struct EthBlockAccountStorageTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub acct_witness: EthAccountTraceWitness<F>,
    pub storage_witness: Vec<EthStorageTraceWitness<F>>,
    pub ebc_rule_witness: EthEbcRuleTraceWitness<F>,
}

#[derive(Clone, Debug)]
pub struct EbcRuleConfig<F: Field> {
    root_hash: AssignedH256<F>,
    version: AssignedH256<F>,
    enable_time: AssignedH256<F>,
    root_hash_slot: AssignedH256<F>,
    version_slot: AssignedH256<F>,
    enable_time_slot: AssignedH256<F>,
    source_chain_id: AssignedValue<F>,
    source_token: AssignedValue<F>,
    source_min_price: AssignedValue<F>,
    source_max_price: AssignedValue<F>,
    source_with_holding_fee: AssignedValue<F>,
    source_trading_fee: AssignedValue<F>,
    source_response_time: AssignedValue<F>,
    dest_chain_id: AssignedValue<F>,
    dest_token: AssignedValue<F>,
    dest_min_price: AssignedValue<F>,
    dest_max_price: AssignedValue<F>,
    dest_with_holding_fee: AssignedValue<F>,
    dest_trading_fee: AssignedValue<F>,
    dest_response_time: AssignedValue<F>,
}

#[derive(Clone, Debug)]
pub struct EIP1186ResponseDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub mdc_contract_address: AssignedValue<F>,
    pub manage_contract_address: AssignedValue<F>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    // pub slots_values: Vec<(AssignedH256<F>, AssignedH256<F>)>, // (slot key;slot value)
    pub ebc_rule_config: EbcRuleConfig<F>,
    pub address_is_empty: AssignedValue<F>,
    pub slot_is_empty: Vec<AssignedValue<F>>,
}

pub trait EthStorageChip<F: Field> {
    fn parse_account_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        state_root_bytes: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        proof: MPTProof<F>,
    ) -> EthAccountTraceWitness<F>;

    fn parse_account_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthAccountTraceWitness<F>,
    ) -> EthAccountTrace<F>;

    fn parse_storage_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        storage_root_bytes: &[AssignedValue<F>],
        slot_bytes: AssignedBytes<F>,
        proof: MPTProof<F>,
    ) -> EthStorageTraceWitness<F>;

    fn parse_storage_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthStorageTraceWitness<F>,
    ) -> EthStorageTrace<F>;

    fn parse_ebc_rule_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        ebc_rule_root_bytes: &[AssignedValue<F>],
        proof: MPTProof<F>,
    ) -> EthEbcRuleTraceWitness<F>;

    fn parse_ebc_rule_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: EthEbcRuleTraceWitness<F>,
    ) -> EthEbcRuleTrace<F>;

    fn parse_eip1186_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        state_root_bytes: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        acct_pf: MPTProof<F>,
        storage_pfs: Vec<(AssignedBytes<F>, MPTProof<F>)>, // (slot_bytes, storage_proof)
        ebc_rule_pfs: MPTProof<F>,
    ) -> (EthAccountTraceWitness<F>, Vec<EthStorageTraceWitness<F>>, EthEbcRuleTraceWitness<F>)
    where
        Self: Sync;

    fn parse_eip1186_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: (
            EthAccountTraceWitness<F>,
            Vec<EthStorageTraceWitness<F>>,
            EthEbcRuleTraceWitness<F>,
        ),
    ) -> (EthAccountTrace<F>, Vec<EthStorageTrace<F>>, EthEbcRuleTrace<F>);

    // slot and block_hash are big-endian 16-byte
    // inputs have H256 represented in (hi,lo) format as two u128s
    // block number and slot values can be derived from the final trace output
    fn parse_eip1186_proofs_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockStorageInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockAccountStorageTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_eip1186_proofs_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockAccountStorageTraceWitness<F>,
    ) -> EthBlockAccountStorageTrace<F>
    where
        Self: EthBlockHeaderChip<F>;

    fn rlp_field_witnesses_to_uint(
        &self,
        ctx: &mut Context<F>,
        rlp_field_witnesses: Vec<&RlpFieldWitness<F>>,
        num_bytes: Vec<usize>,
    ) -> Vec<AssignedValue<F>>;
}

impl<'chip, F: Field> EthStorageChip<F> for EthChip<'chip, F> {
    fn parse_account_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        state_root_bytes: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        proof: MPTProof<F>,
    ) -> EthAccountTraceWitness<F> {
        assert_eq!(32, proof.key_bytes.len());

        // check key is keccak(addr)
        assert_eq!(addr.len(), 20);
        let hash_query_idx = keccak.keccak_fixed_len(ctx, self.gate(), addr, None);
        let hash_bytes = &keccak.fixed_len_queries[hash_query_idx].output_assigned;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }

        // check MPT root is state root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(state_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse value RLP([nonce, balance, storage_root, code_hash])
        let array_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            proof.value_bytes.clone(),
            &[33, 13, 33, 33],
            false,
        );
        // Check MPT inclusion for:
        // keccak(addr) => RLP([nonce, balance, storage_root, code_hash])
        let mpt_witness = self.parse_mpt_inclusion_phase0(ctx, keccak, proof); // 32, 114, max_depth);

        EthAccountTraceWitness { array_witness, mpt_witness }
    }

    fn parse_account_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthAccountTraceWitness<F>,
    ) -> EthAccountTrace<F> {
        self.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        let array_trace: [_; 4] = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.array_witness, false)
            .field_trace
            .try_into()
            .unwrap();
        let [nonce_trace, balance_trace, storage_root_trace, code_hash_trace] =
            array_trace.map(|trace| trace.field_trace);
        EthAccountTrace { nonce_trace, balance_trace, storage_root_trace, code_hash_trace }
    }

    fn parse_storage_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        storage_root_bytes: &[AssignedValue<F>],
        slot: AssignedBytes<F>,
        proof: MPTProof<F>,
    ) -> EthStorageTraceWitness<F> {
        assert_eq!(32, proof.key_bytes.len());

        // check key is keccak(slot)
        let hash_query_idx = keccak.keccak_fixed_len(ctx, self.gate(), slot, None);
        let hash_bytes = &keccak.fixed_len_queries[hash_query_idx].output_assigned;

        for (hash, key) in hash_bytes.iter().zip(proof.key_bytes.iter()) {
            ctx.constrain_equal(hash, key);
        }
        // check MPT root is storage_root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(storage_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse slot value
        let value_witness =
            self.rlp().decompose_rlp_field_phase0(ctx, proof.value_bytes.clone(), 32);

        // check stroage MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_phase0(ctx, keccak, proof);

        EthStorageTraceWitness { value_witness, mpt_witness }
    }

    fn parse_storage_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthStorageTraceWitness<F>,
    ) -> EthStorageTrace<F> {
        // Comments below just to log what load_rlc_cache calls are done in the internal functions:
        // load_rlc_cache bit_length(2*mpt_witness.key_byte_len)
        self.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.mpt_witness);
        // load rlc_cache bit_length(value_witness.rlp_field.len())
        let value_trace =
            self.rlp().decompose_rlp_field_phase1((ctx_gate, ctx_rlc), witness.value_witness);
        let value_trace = value_trace.field_trace;
        debug_assert_eq!(value_trace.max_len, 32);
        EthStorageTrace { value_trace }
    }

    fn parse_ebc_rule_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        ebc_rule_root_bytes: &[AssignedValue<F>],
        proof: MPTProof<F>,
    ) -> EthEbcRuleTraceWitness<F> {
        // Check whether the MPT root is consistent with the ebc rule root, and the ebc rule root has been recorded on the chain.
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(ebc_rule_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        let ebc_rule_rlp_witness = self.rlp().decompose_rlp_array_phase0(
            ctx,
            proof.value_bytes.clone(),
            &EBC_RULE_FIELDS_MAX_FIELDS_LEN,
            true,
        );

        let ebc_rule_mpt_witness = self.parse_mpt_inclusion_phase0(ctx, keccak, proof);

        EthEbcRuleTraceWitness { ebc_rule_rlp_witness, ebc_rule_mpt_witness }
    }

    fn parse_ebc_rule_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: EthEbcRuleTraceWitness<F>,
    ) -> EthEbcRuleTrace<F> {
        self.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.ebc_rule_mpt_witness);

        let value_trace = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.ebc_rule_rlp_witness, true)
            .field_trace
            .try_into()
            .unwrap();
        EthEbcRuleTrace { value_trace }
    }

    fn parse_eip1186_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        state_root: &[AssignedValue<F>],
        addr: AssignedBytes<F>,
        acct_pf: MPTProof<F>,
        storage_pfs: Vec<(AssignedBytes<F>, MPTProof<F>)>, // (slot_bytes, storage_proof)
        ebc_rule_pfs: MPTProof<F>,
    ) -> (EthAccountTraceWitness<F>, Vec<EthStorageTraceWitness<F>>, EthEbcRuleTraceWitness<F>)
    where
        Self: Sync,
    {
        let ctx = thread_pool.main(FIRST_PHASE);
        let acct_trace = self.parse_account_proof_phase0(ctx, keccak, state_root, addr, acct_pf);
        // ctx dropped
        let storage_root = &acct_trace.get_storage_root().field_cells;

        // parallelize storage proofs
        let storage_trace = parallelize_keccak_phase0(
            thread_pool,
            keccak,
            storage_pfs,
            |ctx, keccak, (slot, storage_pf)| {
                self.parse_storage_proof_phase0(ctx, keccak, storage_root, slot, storage_pf)
            },
        );

        // verify ebc rule proofs
        // storage_trace[ebc_rule_root,ebc_rule_version]
        let ebc_rule_root = &storage_trace[0].value_witness.witness.field_cells;
        let ctx = thread_pool.main(FIRST_PHASE);

        let ebc_trace = self.parse_ebc_rule_proof_phase0(ctx, keccak, ebc_rule_root, ebc_rule_pfs);

        (acct_trace, storage_trace, ebc_trace)
    }

    fn parse_eip1186_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        (acct_witness, storage_witness, ebc_rule_witness): (
            EthAccountTraceWitness<F>,
            Vec<EthStorageTraceWitness<F>>,
            EthEbcRuleTraceWitness<F>,
        ),
    ) -> (EthAccountTrace<F>, Vec<EthStorageTrace<F>>, EthEbcRuleTrace<F>) {
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let acct_trace = self.parse_account_proof_phase1((ctx_gate, ctx_rlc), acct_witness);

        let ebc_rule_trace =
            self.parse_ebc_rule_proof_phase1((ctx_gate, ctx_rlc), ebc_rule_witness);

        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);
        let storage_trace =
            parallelize_phase1(thread_pool, storage_witness, |(ctx_gate, ctx_rlc), witness| {
                self.parse_storage_proof_phase1((ctx_gate, ctx_rlc), witness)
            });
        (acct_trace, storage_trace, ebc_rule_trace)
    }

    fn parse_eip1186_proofs_from_block_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: EthBlockStorageInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (EthBlockAccountStorageTraceWitness<F>, EIP1186ResponseDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let ctx = thread_pool.main(FIRST_PHASE);
        let mdc_contract_address = input.storage.address;
        let mut block_header = input.block_header;
        block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);
        let block_witness =
            self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config);

        let state_root = &block_witness.get_state_root().field_cells;
        let block_hash_hi_lo = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        // compute block number from big-endian bytes
        let block_num_bytes = &block_witness.get_number().field_cells;
        let block_num_len = block_witness.get_number().field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 4);
        let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, 4);

        // verify account + storage proof
        let addr_bytes = uint_to_bytes_be(ctx, self.range(), &mdc_contract_address, 20);
        let (slots, storage_pfs): (Vec<_>, Vec<_>) = input
            .storage
            .storage_pfs
            .into_iter()
            .map(|(slot, storage_pf)| {
                let slot_bytes =
                    slot.iter().map(|u128| uint_to_bytes_be(ctx, self.range(), u128, 16)).concat();
                (slot, (slot_bytes, storage_pf))
            })
            .unzip();
        // drop ctx
        let (acct_witness, storage_witness, ebc_rule_witness) = self.parse_eip1186_proofs_phase0(
            thread_pool,
            keccak,
            state_root,
            addr_bytes,
            input.storage.acct_pf,
            storage_pfs,
            input.storage.ebc_rule_pfs,
        );

        let ctx = thread_pool.main(FIRST_PHASE);
        let slots_values = slots
            .into_iter()
            .zip(storage_witness.iter())
            .map(|(slot, witness)| {
                // get value as U256 from RLP decoding, convert to H256, then to hi-lo
                let value_bytes = &witness.value_witness.witness.field_cells;
                let value_len = witness.value_witness.witness.field_len;
                let value_bytes =
                    bytes_be_var_to_fixed(ctx, self.gate(), value_bytes, value_len, 32);
                let value: [_; 2] =
                    bytes_be_to_u128(ctx, self.gate(), &value_bytes).try_into().unwrap();
                (slot, value)
            })
            .collect_vec();

        // ebc rule config
        let mut ebc_rule_config;
        {
            let rlp_field_witnesses = vec![
                ebc_rule_witness.get_source_chain_id(),
                ebc_rule_witness.get_source_token(),
                ebc_rule_witness.get_source_min_price(),
                ebc_rule_witness.get_source_max_price(),
                ebc_rule_witness.get_source_with_holding_fee(),
                ebc_rule_witness.get_source_trading_fee(),
                ebc_rule_witness.get_source_response_time(),
                ebc_rule_witness.get_dest_chain_id(),
                ebc_rule_witness.get_dest_token(),
                ebc_rule_witness.get_dest_min_price(),
                ebc_rule_witness.get_dest_max_price(),
                ebc_rule_witness.get_dest_with_holding_fee(),
                ebc_rule_witness.get_dest_trading_fee(),
                ebc_rule_witness.get_dest_response_time(),
            ];
            let num_bytes = vec![8, 32, 16, 16, 16, 4, 4, 8, 32, 16, 16, 16, 4, 4];
            let ebc_rule_fields =
                self.rlp_field_witnesses_to_uint(ctx, rlp_field_witnesses, num_bytes);
            ebc_rule_config = EbcRuleConfig {
                root_hash: slots_values[0].1,
                version: slots_values[1].1,
                enable_time: slots_values[2].1,
                root_hash_slot: slots_values[0].0,
                version_slot: slots_values[1].0,
                enable_time_slot: slots_values[2].0,
                source_chain_id: ebc_rule_fields[0],
                source_token: ebc_rule_fields[1],
                source_min_price: ebc_rule_fields[2],
                source_max_price: ebc_rule_fields[3],
                source_with_holding_fee: ebc_rule_fields[4],
                source_trading_fee: ebc_rule_fields[5],
                source_response_time: ebc_rule_fields[6],
                dest_chain_id: ebc_rule_fields[7],
                dest_token: ebc_rule_fields[8],
                dest_min_price: ebc_rule_fields[9],
                dest_max_price: ebc_rule_fields[10],
                dest_with_holding_fee: ebc_rule_fields[11],
                dest_trading_fee: ebc_rule_fields[12],
                dest_response_time: ebc_rule_fields[13],
            };
        }

        let digest = EIP1186ResponseDigest {
            block_hash: block_hash_hi_lo.try_into().unwrap(),
            block_number,
            mdc_contract_address,
            manage_contract_address: mdc_contract_address, // The status of the manage contract has not been proved yet, so the same address is used temporarily.
            ebc_rule_config,
            address_is_empty: acct_witness.mpt_witness.slot_is_empty,
            slot_is_empty: storage_witness
                .iter()
                .map(|witness| witness.mpt_witness.slot_is_empty)
                .collect_vec(),
        };
        (
            EthBlockAccountStorageTraceWitness {
                block_witness,
                acct_witness,
                storage_witness,
                ebc_rule_witness,
            },
            digest,
        )
    }

    fn parse_eip1186_proofs_from_block_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: EthBlockAccountStorageTraceWitness<F>,
    ) -> EthBlockAccountStorageTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let block_trace =
            self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witness.block_witness);
        let (acct_trace, storage_trace, ebc_rule_trace) = self.parse_eip1186_proofs_phase1(
            thread_pool,
            (witness.acct_witness, witness.storage_witness, witness.ebc_rule_witness),
        );
        EthBlockAccountStorageTrace { block_trace, acct_trace, storage_trace, ebc_rule_trace }
    }

    fn rlp_field_witnesses_to_uint(
        &self,
        ctx: &mut Context<F>,
        rlp_field_witnesses: Vec<&RlpFieldWitness<F>>,
        num_bytes: Vec<usize>,
    ) -> Vec<AssignedValue<F>> {
        let assigned_values = rlp_field_witnesses
            .iter()
            .zip(num_bytes.iter())
            .map(|(witness, num_byte)| {
                let rlp_field_witness_bytes = &witness.field_cells;
                let rlp_field_witness_len = witness.field_len;
                let _rlp_field = bytes_be_var_to_fixed(
                    ctx,
                    self.gate(),
                    rlp_field_witness_bytes,
                    rlp_field_witness_len,
                    *num_byte,
                );
                bytes_be_to_uint(ctx, self.gate(), &_rlp_field, *num_byte)
            })
            .collect_vec();
        assigned_values
    }
}

#[derive(Clone, Debug)]
pub struct EbcRuleVersion {
    pub version: u32,
}

/// slot :struct RootWithVersion
///   {
///         bytes32 root;
///         uint32 version;
///   }
///   mapping(address => RuleLib.RootWithVersion) private _rulesRoots; // ebc => merkleRoot(rules), version
/// 1. slot mpt
/// 2. slot.value(contract) == EbcRulePfs.MPTFixedKeyInput.rootHash
/// 3. EbcRulePfs.MPTFixedKeyInput mpt => EbcRuleConfig
/// 4. decode rlp EbcRuleConfig
/// 5. output EbcRuleConfig、version
#[derive(Clone, Debug)]
pub struct EthStorageInput {
    pub addr: Address,
    // MDC
    pub acct_pf: MPTInput,
    pub storage_pfs: Vec<(H256, U256, MPTInput)>,
    // (slot, value, proof)
    pub ebc_rule_pfs: MPTInput, // key:keccak256(chain_id0, chain_id1, token0, token1) value:rule_config_rlp
}

#[derive(Clone, Debug)]
pub struct EthStorageInputAssigned<F: Field> {
    pub address: AssignedValue<F>,
    // U160
    pub acct_pf: MPTProof<F>,
    pub storage_pfs: Vec<(AssignedH256<F>, MPTProof<F>)>,
    // (slot, proof) where slot is H256 as (u128, u128)
    pub ebc_rule_pfs: MPTProof<F>,
}

impl EthStorageInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthStorageInputAssigned<F> {
        let address = encode_addr_to_field(&self.addr);
        let address = ctx.load_witness(address);
        let acct_pf = self.acct_pf.assign(ctx);
        let storage_pfs = self
            .storage_pfs
            .into_iter()
            .map(|(slot, _, pf)| {
                let slot = encode_h256_to_field(&slot);
                let slot = slot.map(|slot| ctx.load_witness(slot));
                let pf = pf.assign(ctx);
                (slot, pf)
            })
            .collect();
        let ebc_rule_pfs = self.ebc_rule_pfs.assign(ctx);
        EthStorageInputAssigned { address, acct_pf, storage_pfs, ebc_rule_pfs }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageInput {
    pub block: Block<H256>,
    pub block_number: u32,
    pub block_hash: H256,
    // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
    pub storage: EthStorageInput,
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageInputAssigned<F: Field> {
    // block_hash: AssignedH256<F>, // H256 as (u128, u128)
    pub block_header: Vec<u8>,
    pub storage: EthStorageInputAssigned<F>,
}

impl EthBlockStorageInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthBlockStorageInputAssigned<F> {
        // let block_hash = encode_h256_to_field(&self.block_hash);
        // let block_hash = block_hash.map(|block_hash| ctx.load_witness(block_hash));
        let storage = self.storage.assign(ctx);
        EthBlockStorageInputAssigned { block_header: self.block_header, storage }
    }
}

#[derive(Clone, Debug)]
pub struct EthBlockStorageCircuit {
    pub inputs: EthBlockStorageInput,
    pub block_header_config: BlockHeaderConfig,
}

impl EthBlockStorageCircuit {
    #[cfg(feature = "providers")]
    pub fn from_provider(provider: &Provider<Http>, constructor: StorageConstructor) -> Self {
        let inputs = get_storage_input(
            provider,
            constructor.block_number,
            constructor.address,
            constructor.slots,
            constructor.acct_pf_max_depth,
            constructor.storage_pf_max_depth,
            constructor.ebc_rule_params,
        );
        let block_header_config = get_block_header_config(&constructor.network);
        Self { inputs, block_header_config }
    }

    // MAYBE UNUSED
    // blockHash, blockNumber, address, (slot, value)s
    // with H256 encoded as hi-lo (u128, u128)
    pub fn instance<F: Field>(&self) -> Vec<F> {
        let EthBlockStorageInput { block_number, block_hash, storage, .. } = &self.inputs;
        let EthStorageInput { addr, storage_pfs, .. } = storage;
        let mut instance = Vec::with_capacity(4 + 4 * storage_pfs.len());
        instance.extend(encode_h256_to_field::<F>(block_hash));
        instance.push(F::from(*block_number as u64));
        instance.push(encode_addr_to_field(addr));
        for (slot, value, _) in storage_pfs {
            instance.extend(encode_h256_to_field::<F>(slot));
            instance.extend(encode_u256_to_field::<F>(value));
            // instance for input
        }
        instance
    }
}

impl EthPreCircuit for EthBlockStorageCircuit {
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
        let (witness, digest) = chip.parse_eip1186_proofs_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            &self.block_header_config,
        );
        let EIP1186ResponseDigest {
            block_hash,
            block_number,
            mdc_contract_address,
            manage_contract_address,
            ebc_rule_config,
            address_is_empty,
            slot_is_empty,
        } = digest;

        let assigned_instances = block_hash
            .into_iter()
            .chain([block_number, mdc_contract_address, manage_contract_address])
            .chain(ebc_rule_config.root_hash.into_iter())
            .chain(ebc_rule_config.version.into_iter())
            .chain(ebc_rule_config.enable_time.into_iter())
            .chain(ebc_rule_config.root_hash_slot.into_iter())
            .chain(ebc_rule_config.version_slot.into_iter())
            .chain(ebc_rule_config.enable_time_slot.into_iter())
            .chain([
                ebc_rule_config.source_chain_id,
                ebc_rule_config.source_token,
                ebc_rule_config.source_min_price,
                ebc_rule_config.source_max_price,
                ebc_rule_config.source_with_holding_fee,
                ebc_rule_config.source_trading_fee,
                ebc_rule_config.source_response_time,
                ebc_rule_config.dest_chain_id,
                ebc_rule_config.dest_token,
                ebc_rule_config.dest_min_price,
                ebc_rule_config.dest_max_price,
                ebc_rule_config.dest_with_holding_fee,
                ebc_rule_config.dest_trading_fee,
                ebc_rule_config.dest_response_time,
            ])
            .collect_vec();

        // For now this circuit is going to constrain that all slots are occupied. We can also create a circuit that exposes the bitmap of slot_is_empty
        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            range.gate.assert_is_const(ctx, &address_is_empty, &Fr::zero());
            for slot_is_empty in slot_is_empty {
                range.gate.assert_is_const(ctx, &slot_is_empty, &Fr::zero());
            }
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
                let _trace = chip.parse_eip1186_proofs_from_block_phase1(builder, witness);
            },
        )
    }
}
