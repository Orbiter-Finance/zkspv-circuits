mod tests;
pub mod util;

use crate::block_header::{get_block_header_config, BlockHeaderConfig, EthBlockHeaderChip};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{MPTInput, MPTProof, MPTProofWitness};
use crate::providers::get_contract_storage_input;
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{RlcContextPair, FIRST_PHASE};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness};
use crate::storage::contract_storage::util::MultiBlocksContractsStorageConstructor;
use crate::storage::util::StorageConstructor;
use crate::storage::{
    EIP1186ResponseDigest, EthBlockAccountStorageTrace, EthBlockAccountStorageTraceWitness,
    EthBlockStorageInput, EthBlockStorageInputAssigned, EthStorageChip, EthStorageInput,
    EthStorageInputAssigned, EthStorageTraceWitness,
};
use crate::util::{encode_addr_to_field, encode_h256_to_field, AssignedH256};
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, ETH_LOOKUP_BITS};
use ethers_core::types::{Address, Block, H256, U256};
use ethers_providers::{Http, Provider};
use futures::AsyncReadExt;
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions, RangeChip},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};
use itertools::Itertools;
use snark_verifier::loader::halo2::IntegerInstructions;
use std::cell::RefCell;
use tokio_stream::StreamExt;
use zkevm_keccak::util::eth_types::Field;

const CACHE_BITS: usize = 10;
const EBC_RULE_FIELDS_NUM: usize = 18;
const EBC_RULE_FIELDS_MAX_FIELDS_LEN: [usize; EBC_RULE_FIELDS_NUM] =
    [8, 8, 1, 1, 32, 32, 16, 16, 16, 16, 16, 16, 4, 4, 4, 4, 4, 4];

#[derive(Clone, Debug)]
pub struct EbcRule<F: Field> {
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
pub struct BlockInput {
    pub block: Block<H256>,
    pub block_number: u32,
    pub block_hash: H256,
    // provided for convenience, actual block_hash is computed from block_header
    pub block_header: Vec<u8>,
}

/**
- contract slot
```solidity
struct RootWithVersion{
    bytes32 root;
    uint32 version;
}
mapping(address => RootWithVersion) private _rulesRoots; // ebc => merkleRoot(rules), version
```
1. slot mpt
2. slot.value(contract) == EbcRulePfs.MPTFixedKeyInput.rootHash
3. EbcRulePfs.MPTFixedKeyInput mpt => EbcRuleConfig
4. decode rlp EbcRuleConfig
5. output EbcRuleConfig、version
 */
#[derive(Clone, Debug)]
pub struct ObContractsStorageInput {
    pub contracts_storage: Vec<EthStorageInput>,
    pub ebc_rules_pfs: MPTInput,
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageInputAssigned<F: Field> {
    pub contracts_storage: Vec<EthStorageInputAssigned<F>>,
    pub ebc_rules_pfs: MPTProof<F>,
}

impl ObContractsStorageInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ObContractsStorageInputAssigned<F> {
        let contracts_storage = self
            .contracts_storage
            .into_iter()
            .map(|contract_storage| contract_storage.assign(ctx))
            .collect_vec();
        let ebc_rules_pfs = self.ebc_rules_pfs.assign(ctx);
        ObContractsStorageInputAssigned { contracts_storage, ebc_rules_pfs }
    }
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageBlockInput {
    pub contract_storage_block: Vec<(BlockInput, ObContractsStorageInput)>,
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageBlockInputAssigned<F: Field> {
    pub contract_storage_block: Vec<(Vec<u8>, ObContractsStorageInputAssigned<F>)>,
}

impl ObContractsStorageBlockInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ObContractsStorageBlockInputAssigned<F> {
        let contract_storage_block = self
            .contract_storage_block
            .into_iter()
            .map(|(block, contracts_storage)| {
                let block_header = block.block_header;
                let contracts_storage = contracts_storage.assign(ctx);
                (block_header, contracts_storage)
            })
            .collect();

        ObContractsStorageBlockInputAssigned { contract_storage_block }
    }
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageCircuit {
    pub inputs: ObContractsStorageBlockInput,
    pub block_header_config: BlockHeaderConfig,
}

impl ObContractsStorageCircuit {
    #[cfg(feature = "providers")]
    pub fn from_provider(
        provider: &Provider<Http>,
        constructor: MultiBlocksContractsStorageConstructor,
    ) -> Self {
        let inputs = get_contract_storage_input(provider, constructor.clone());
        let block_header_config = get_block_header_config(&constructor.network);
        Self { inputs, block_header_config }
    }
}

impl EthPreCircuit for ObContractsStorageCircuit {
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

        let (witnesses, digests) = chip.parse_multi_block_contract_storages_proofs_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            &self.block_header_config,
        );

        let only_one_digest = digests[0].clone();

        // load contract address and slots value
        let assigned_instances: Vec<_> = only_one_digest
            .contracts_address
            .into_iter()
            .chain(
                only_one_digest
                    .slots_values
                    .into_iter()
                    .flat_map(|(slot, value)| slot.into_iter().chain(value.into_iter())),
            )
            .chain([
                only_one_digest.ebc_rule.source_chain_id,
                only_one_digest.ebc_rule.source_token,
                only_one_digest.ebc_rule.source_min_price,
                only_one_digest.ebc_rule.source_max_price,
                only_one_digest.ebc_rule.source_with_holding_fee,
                only_one_digest.ebc_rule.source_trading_fee,
                only_one_digest.ebc_rule.source_response_time,
                only_one_digest.ebc_rule.dest_chain_id,
                only_one_digest.ebc_rule.dest_token,
                only_one_digest.ebc_rule.dest_min_price,
                only_one_digest.ebc_rule.dest_max_price,
                only_one_digest.ebc_rule.dest_with_holding_fee,
                only_one_digest.ebc_rule.dest_trading_fee,
                only_one_digest.ebc_rule.dest_response_time,
            ])
            .chain(
                digests
                    .clone()
                    .into_iter()
                    .flat_map(|d| d.block_hash.into_iter().chain([d.block_number])),
            )
            .collect();

        // println!("value:{:?}", &assigned_instances);

        // For now this circuit is going to constrain that all slots are occupied. We can also create a circuit that exposes the bitmap of slot_is_empty
        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            for digest in digests {
                for address_is_empty in digest.address_is_empty {
                    range.gate.assert_is_const(ctx, &address_is_empty, &Fr::zero());
                }
                for slots_is_empty in digest.slots_is_empty {
                    for slot_is_empty in slots_is_empty {
                        range.gate.assert_is_const(ctx, &slot_is_empty, &Fr::zero());
                    }
                }
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
                let _trace =
                    chip.parse_multi_block_contract_storages_proofs_phase1(builder, witnesses);
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct ObEbcRuleTrace<F: Field> {
    pub value_trace: Vec<RlpFieldTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ObEbcRuleTraceWitness<F: Field> {
    ebc_rule_rlp_witness: RlpArrayTraceWitness<F>,
    ebc_rule_mpt_witness: MPTProofWitness<F>,
}

impl<F: Field> ObEbcRuleTraceWitness<F> {
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

/**
block_hash
block_number
contracts_address
ebc_rule
contracts_address_is_empty
slots_is_empty
 */
#[derive(Clone, Debug)]
pub struct ObSingleBlockContractsDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub contracts_address: Vec<AssignedValue<F>>,
    // the value U256 is interpreted as H256 (padded with 0s on left)
    pub slots_values: Vec<(AssignedH256<F>, AssignedH256<F>)>, // (slot key;slot value)
    pub ebc_rule: EbcRule<F>,
    pub address_is_empty: Vec<AssignedValue<F>>,
    pub slots_is_empty: Vec<Vec<AssignedValue<F>>>,
}

#[derive(Clone, Debug)]
pub struct ObSingleBlockContractsTrace<F: Field> {
    pub mdc_storages_trace: EthBlockAccountStorageTrace<F>,
    pub manage_storages_trace: EthBlockAccountStorageTrace<F>,
    pub ebc_trace: ObEbcRuleTrace<F>,
}

#[derive(Clone, Debug)]
pub struct ObContractsStoragesTrace<F: Field> {
    pub contracts_storages_trace: Vec<ObSingleBlockContractsTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageTraceWitness<F: Field> {
    pub mdc_storage_trace_witness: EthBlockAccountStorageTraceWitness<F>,
    pub manage_storage_trace_witness: EthBlockAccountStorageTraceWitness<F>,
    pub ebc_rule_trace_witness: ObEbcRuleTraceWitness<F>,
}

pub trait ObContractsStorageChip<F: Field> {
    fn parse_multi_block_contract_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ObContractsStorageBlockInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (Vec<ObContractsStorageTraceWitness<F>>, Vec<ObSingleBlockContractsDigest<F>>)
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_single_block_contract_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: (Vec<u8>, ObContractsStorageInputAssigned<F>),
        block_header_config: &BlockHeaderConfig,
    ) -> (ObContractsStorageTraceWitness<F>, ObSingleBlockContractsDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_ebc_rule_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        ebc_rule_root_witness: EthStorageTraceWitness<F>,
        proof: MPTProof<F>,
    ) -> ObEbcRuleTraceWitness<F>;

    fn parse_multi_block_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<ObContractsStorageTraceWitness<F>>,
    ) -> ObContractsStoragesTrace<F>
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_single_block_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: (
            EthBlockAccountStorageTraceWitness<F>,
            EthBlockAccountStorageTraceWitness<F>,
            ObEbcRuleTraceWitness<F>,
        ),
    ) -> ObSingleBlockContractsTrace<F>
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_ebc_rule_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: ObEbcRuleTraceWitness<F>,
    ) -> ObEbcRuleTrace<F>;
}

impl<'chip, F: Field> ObContractsStorageChip<F> for EthChip<'chip, F> {
    fn parse_multi_block_contract_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ObContractsStorageBlockInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (Vec<ObContractsStorageTraceWitness<F>>, Vec<ObSingleBlockContractsDigest<F>>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let (witnesses, digests): (
            Vec<ObContractsStorageTraceWitness<F>>,
            Vec<ObSingleBlockContractsDigest<F>>,
        ) = input
            .contract_storage_block
            .into_iter()
            .map(|(block_header, contracts_storage)| {
                self.parse_single_block_contract_storages_proofs_phase0(
                    thread_pool,
                    keccak,
                    (block_header, contracts_storage),
                    block_header_config,
                )
            })
            .unzip();

        (witnesses, digests)
    }

    fn parse_single_block_contract_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        (block_header, contracts_storage): (Vec<u8>, ObContractsStorageInputAssigned<F>),
        block_header_config: &BlockHeaderConfig,
    ) -> (ObContractsStorageTraceWitness<F>, ObSingleBlockContractsDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let eth_block_storage_input_assigned_for_mdc = EthBlockStorageInputAssigned {
            block_header: block_header.to_vec(),
            storage: contracts_storage.contracts_storage[0].clone(),
        };

        let (mdc_storage_trace_witness, mdc_digest) = self.parse_eip1186_proofs_from_block_phase0(
            thread_pool,
            keccak,
            eth_block_storage_input_assigned_for_mdc,
            block_header_config,
        );

        let eth_block_storage_input_assigned_for_manage = EthBlockStorageInputAssigned {
            block_header: block_header.to_vec(),
            storage: contracts_storage.contracts_storage[1].clone(),
        };
        let (manage_storage_trace_witness, manage_digest) = self
            .parse_eip1186_proofs_from_block_phase0(
                thread_pool,
                keccak,
                eth_block_storage_input_assigned_for_manage,
                block_header_config,
            );

        // ebc rule
        let ctx = thread_pool.main(FIRST_PHASE);
        let ebc_rule_root_witness = mdc_storage_trace_witness.storage_witness[0].clone();
        let ebc_rule_trace_witness = self.parse_ebc_rule_proof_phase0(
            ctx,
            keccak,
            ebc_rule_root_witness,
            contracts_storage.ebc_rules_pfs,
        );

        let mut ebc_rule_digest;
        {
            let rlp_field_witnesses = vec![
                ebc_rule_trace_witness.get_source_chain_id(),
                ebc_rule_trace_witness.get_source_token(),
                ebc_rule_trace_witness.get_source_min_price(),
                ebc_rule_trace_witness.get_source_max_price(),
                ebc_rule_trace_witness.get_source_with_holding_fee(),
                ebc_rule_trace_witness.get_source_trading_fee(),
                ebc_rule_trace_witness.get_source_response_time(),
                ebc_rule_trace_witness.get_dest_chain_id(),
                ebc_rule_trace_witness.get_dest_token(),
                ebc_rule_trace_witness.get_dest_min_price(),
                ebc_rule_trace_witness.get_dest_max_price(),
                ebc_rule_trace_witness.get_dest_with_holding_fee(),
                ebc_rule_trace_witness.get_dest_trading_fee(),
                ebc_rule_trace_witness.get_dest_response_time(),
            ];
            let num_bytes = vec![8, 32, 16, 16, 16, 4, 4, 8, 32, 16, 16, 16, 4, 4];
            let ebc_rule_fields =
                self.rlp_field_witnesses_to_uint(ctx, rlp_field_witnesses, num_bytes);
            ebc_rule_digest = EbcRule {
                source_chain_id: ebc_rule_fields[0].clone(),
                source_token: ebc_rule_fields[1].clone(),
                source_min_price: ebc_rule_fields[2].clone(),
                source_max_price: ebc_rule_fields[3].clone(),
                source_with_holding_fee: ebc_rule_fields[4].clone(),
                source_trading_fee: ebc_rule_fields[5].clone(),
                source_response_time: ebc_rule_fields[6].clone(),
                dest_chain_id: ebc_rule_fields[7].clone(),
                dest_token: ebc_rule_fields[8].clone(),
                dest_min_price: ebc_rule_fields[9].clone(),
                dest_max_price: ebc_rule_fields[10].clone(),
                dest_with_holding_fee: ebc_rule_fields[11].clone(),
                dest_trading_fee: ebc_rule_fields[12].clone(),
                dest_response_time: ebc_rule_fields[13].clone(),
            };
        }

        // {
        //     self.range().gate.assert_equal(ctx, &mdc_digest.block_hash, &manage_digest.block_hash);
        //     self.range().gate.assert_equal(
        //         ctx,
        //         &mdc_digest.block_number,
        //         &manage_digest.block_number,
        //     );
        // }

        let slots_values = [mdc_digest.slots_values, manage_digest.slots_values].concat();

        (
            ObContractsStorageTraceWitness {
                mdc_storage_trace_witness,
                manage_storage_trace_witness,
                ebc_rule_trace_witness,
            },
            ObSingleBlockContractsDigest {
                block_hash: mdc_digest.block_hash,
                block_number: mdc_digest.block_number,
                contracts_address: vec![mdc_digest.address, manage_digest.address],
                slots_values,
                ebc_rule: ebc_rule_digest,
                address_is_empty: vec![mdc_digest.address_is_empty, manage_digest.address_is_empty],
                slots_is_empty: vec![mdc_digest.slot_is_empty, manage_digest.slot_is_empty],
            },
        )
    }

    fn parse_ebc_rule_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        ebc_rule_root_witness: EthStorageTraceWitness<F>,
        proof: MPTProof<F>,
    ) -> ObEbcRuleTraceWitness<F> {
        let ebc_rule_root_bytes = ebc_rule_root_witness.value_witness.witness.field_cells;
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

        ObEbcRuleTraceWitness { ebc_rule_rlp_witness, ebc_rule_mpt_witness }
    }

    fn parse_multi_block_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: Vec<ObContractsStorageTraceWitness<F>>,
    ) -> ObContractsStoragesTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let contracts_storages_trace = witnesses
            .into_iter()
            .map(|witness| {
                self.parse_single_block_contract_storages_proofs_phase1(
                    thread_pool,
                    (
                        witness.mdc_storage_trace_witness,
                        witness.manage_storage_trace_witness,
                        witness.ebc_rule_trace_witness,
                    ),
                )
            })
            .collect();
        ObContractsStoragesTrace { contracts_storages_trace }
    }

    fn parse_single_block_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        account_storage_trace_witnesses: (
            EthBlockAccountStorageTraceWitness<F>,
            EthBlockAccountStorageTraceWitness<F>,
            ObEbcRuleTraceWitness<F>,
        ),
    ) -> ObSingleBlockContractsTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let mdc_storages_trace = self
            .parse_eip1186_proofs_from_block_phase1(thread_pool, account_storage_trace_witnesses.0);
        let manage_storages_trace = self
            .parse_eip1186_proofs_from_block_phase1(thread_pool, account_storage_trace_witnesses.1);
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();

        let ebc_trace = self
            .parse_ebc_rule_proof_phase1((ctx_gate, ctx_rlc), account_storage_trace_witnesses.2);

        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);

        ObSingleBlockContractsTrace { mdc_storages_trace, manage_storages_trace, ebc_trace }
    }

    fn parse_ebc_rule_proof_phase1(
        &self,
        (ctx_gate, ctx_rlc): RlcContextPair<F>,
        witness: ObEbcRuleTraceWitness<F>,
    ) -> ObEbcRuleTrace<F> {
        self.parse_mpt_inclusion_phase1((ctx_gate, ctx_rlc), witness.ebc_rule_mpt_witness);

        let value_trace = self
            .rlp()
            .decompose_rlp_array_phase1((ctx_gate, ctx_rlc), witness.ebc_rule_rlp_witness, true)
            .field_trace
            .try_into()
            .unwrap();
        ObEbcRuleTrace { value_trace }
    }
}
