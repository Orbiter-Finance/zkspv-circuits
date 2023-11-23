mod tests;

pub mod util;

use crate::block_header::{
    get_block_header_config, BlockHeaderConfig, EthBlockHeaderChip, EthBlockHeaderTrace,
    EthBlockHeaderTraceWitness,
};
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::mpt::{AssignedBytes, MPTInput, MPTProof, MPTProofWitness};
use crate::providers::get_contract_storage_input;
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::{RlcContextPair, FIRST_PHASE};
use crate::rlp::{RlpArrayTraceWitness, RlpChip, RlpFieldTrace, RlpFieldWitness};
use crate::storage::contract_storage::util::MultiBlocksContractsStorageConstructor;
use crate::storage::{
    EthAccountTrace, EthAccountTraceWitness, EthStorageChip, EthStorageInput,
    EthStorageInputAssigned, EthStorageTrace, EthStorageTraceWitness,
};
use crate::util::{
    bytes_be_to_u128, bytes_be_to_uint, bytes_be_var_to_fixed, uint_to_bytes_be, AssignedH256,
};
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, ETH_LOOKUP_BITS};
use ethers_core::types::{Block, H256};
use ethers_providers::{Http, Provider};
use futures::{AsyncReadExt, FutureExt};
use halo2_base::gates::RangeInstructions;
use halo2_base::QuantumCell::Constant;
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions, RangeChip},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};
use itertools::Itertools;
use std::cell::RefCell;
use std::io::Read;
use tokio_stream::StreamExt;
use zkevm_keccak::util::eth_types::Field;

const CACHE_BITS: usize = 10;
const EBC_RULE_FIELDS_NUM: usize = 18;
const EBC_RULE_FIELDS_MAX_FIELDS_LEN: [usize; EBC_RULE_FIELDS_NUM] =
    [8, 8, 1, 1, 32, 32, 16, 16, 16, 16, 16, 16, 4, 4, 4, 4, 4, 4];
pub(crate) const EBC_RULE_PROOF_VALUE_MAX_BYTE_LEN: usize = 140;

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
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageInputAssigned<F: Field> {
    pub contracts_storage: Vec<EthStorageInputAssigned<F>>,
}

impl ObContractsStorageInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> ObContractsStorageInputAssigned<F> {
        let contracts_storage = self
            .contracts_storage
            .into_iter()
            .map(|contract_storage| contract_storage.assign(ctx))
            .collect_vec();

        ObContractsStorageInputAssigned { contracts_storage }
    }
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageBlockInput {
    pub contract_storage_block: Vec<(BlockInput, ObContractsStorageInput)>,
    pub ebc_rules_pfs: MPTInput,
}

#[derive(Clone, Debug)]
pub struct ObContractsStorageBlockInputAssigned<F: Field> {
    pub contract_storage_block: Vec<(Vec<u8>, ObContractsStorageInputAssigned<F>)>,
    pub ebc_rules_pfs: MPTProof<F>,
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
        let ebc_rules_pfs = self.ebc_rules_pfs.assign(ctx);

        ObContractsStorageBlockInputAssigned { contract_storage_block, ebc_rules_pfs }
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

        let (witnesses, digests) = chip.parse_multi_blocks_contracts_storages_proofs_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            input,
            &self.block_header_config,
        );

        let only_one_digest = digests.multi_blocks_contracts_digest[0].clone();

        let slots_key = only_one_digest
            .clone()
            .slots_values
            .into_iter()
            .map(|(slot, value)| slot)
            .collect_vec();

        /**
        1. mdc_current_rule_root,
        2. mdc_current_rule_version,
        3. mdc_current_rule_enable_time,
        4. mdc_current_column_array_hash,
        5. mdc_current_response_makers_hash,
        6. manage_current_source_chain_info,
        7. manage_current_source_chain_mainnet_token_info,
        8. manage_current_dest_chain_mainnet_token,
        9. manage_current_challenge_user_ratio,
        10. mdc_next_rule_version,
        11. mdc_next_rule_enable_time
        */
        let slots_value_into_public =
            vec![vec![true, false, true, true, true, true, true, true, true], vec![false, true]];

        let slots_values_public = digests
            .multi_blocks_contracts_digest
            .clone()
            .into_iter()
            .zip(slots_value_into_public.clone().into_iter())
            .map(|(d, is_public)| {
                d.slots_values
                    .into_iter()
                    .zip(is_public.into_iter())
                    .filter_map(
                        |((slot, value), is_public)| {
                            if is_public {
                                Some(value)
                            } else {
                                None
                            }
                        },
                    )
                    .collect_vec()
            })
            .collect_vec();

        let slots_value = slots_values_public
            .clone()
            .into_iter()
            .map(|d| d.into_iter().flat_map(|value| value.into_iter()))
            .collect_vec();

        // load contract address and slots value
        let assigned_instances: Vec<_> = only_one_digest
            .contracts_address
            .into_iter()
            .chain(slots_key.into_iter().flat_map(|slot| slot.into_iter()))
            .chain(slots_value.into_iter().flat_map(|value| value))
            .chain(digests.ebc_rule_hash.clone().into_iter())
            // Todo: At present, it is reused, which affects public input, so it is commented out here, and this parameter does not need to be exposed after the aggregation circuit is actually completed.
            // .chain(
            //     digests
            //         .clone()
            //         .into_iter()
            //         .flat_map(|d| d.block_hash.into_iter().chain([d.block_number])),
            // )
            .collect();

        // For now this circuit is going to constrain that all slots are occupied. We can also create a circuit that exposes the bitmap of slot_is_empty
        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            assert_eq!(digests.multi_blocks_contracts_digest.len(), 2);

            for (current_single_block_contracts_digest, next_single_block_contracts_digest) in
                digests
                    .multi_blocks_contracts_digest
                    .iter()
                    .zip(digests.multi_blocks_contracts_digest.iter().skip(1))
            {
                // Check mdc_current_rule_block_number and mdc_next_rule_block_number, that is, mdc_current_rule_block_number must be less than mdc_next_rule_block_number.
                // range.check_less_than(
                //     ctx,
                //     current_single_block_contracts_digest.block_number,
                //     next_single_block_contracts_digest.block_number,
                //     8,
                // );

                // Check mdc_current_rule_version and mdc_next_rule_version, that is, mdc_current_rule_version must be less than or equal to mdc_next_rule_version.
                //
                // let current_version = current_single_block_contracts_digest.slots_values[1].1;
                // let current_version = current_version.as_slice()[1];
                // let next_version = next_single_block_contracts_digest.slots_values[0].1;
                // let next_version = next_version.as_slice()[1];
                //
                // let diff_version = chip.gate().sub(ctx, next_version, current_version);
                //
                // // diff_version <= 1
                // range.check_less_than(ctx, diff_version, Constant(Fr::from(2)), 8);
            }

            for digest in digests.multi_blocks_contracts_digest {
                for address_is_empty in digest.address_is_empty {
                    range.gate.assert_is_const(ctx, &address_is_empty, &Fr::zero());
                }

                // For Mdc and Mange contracts, some values can be empty, so it is not determined whether the slot is already occupied.

                // for slots_is_empty in digest.slots_is_empty {
                //     for slot_is_empty in slots_is_empty {
                //         range.gate.assert_is_const(ctx, &slot_is_empty, &Fr::zero());
                //     }
                // }
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
                    chip.parse_multi_blocks_contracts_storages_proofs_phase1(builder, witnesses);
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
    ebc_rule_hash: AssignedH256<F>,
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

#[derive(Clone, Debug)]
pub struct ObSingleBlockContractsDigest<F: Field> {
    pub block_hash: AssignedH256<F>,
    pub block_number: AssignedValue<F>,
    pub contracts_address: Vec<AssignedValue<F>>,
    pub slots_values: Vec<(AssignedH256<F>, AssignedH256<F>)>,
    pub address_is_empty: Vec<AssignedValue<F>>,
    pub slots_is_empty: Vec<Vec<AssignedValue<F>>>,
}

#[derive(Clone, Debug)]
pub struct ObMultiBlocksContractsDigest<F: Field> {
    pub multi_blocks_contracts_digest: Vec<ObSingleBlockContractsDigest<F>>,
    pub ebc_rule_hash: AssignedH256<F>,
}

#[derive(Clone, Debug)]
pub struct ObContractStoragesDigest<F: Field> {
    pub address: AssignedValue<F>,
    pub slots_values: Vec<(AssignedH256<F>, AssignedH256<F>)>,
    pub address_is_empty: AssignedValue<F>,
    pub slot_is_empty: Vec<AssignedValue<F>>,
}

#[derive(Clone, Debug)]
pub struct ObAccountStorageTrace<F: Field> {
    pub acct_trace: EthAccountTrace<F>,
    pub storage_trace: Vec<EthStorageTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ObSingleBlockContractsTrace<F: Field> {
    pub block_trace: EthBlockHeaderTrace<F>,
    pub contracts_storages_trace: Vec<ObAccountStorageTrace<F>>,
}

#[derive(Clone, Debug)]
pub struct ObContractsStoragesTrace<F: Field> {
    pub contracts_trace: Vec<ObSingleBlockContractsTrace<F>>,
    pub ebc_trace: ObEbcRuleTrace<F>,
}

#[derive(Clone, Debug)]
pub struct ObAccountStorageTraceWitness<F: Field> {
    pub acct_witness: EthAccountTraceWitness<F>,
    pub storage_witness: Vec<EthStorageTraceWitness<F>>,
}

#[derive(Clone, Debug)]
pub struct ObSingleBlockContractsStorageTraceWitness<F: Field> {
    pub block_witness: EthBlockHeaderTraceWitness<F>,
    pub contracts_witnesses: Vec<ObAccountStorageTraceWitness<F>>,
}

#[derive(Clone, Debug)]
pub struct ObMultiBlocksContractsStorageTraceWitness<F: Field> {
    pub multi_blocks_contracts_witness: Vec<ObSingleBlockContractsStorageTraceWitness<F>>,
    pub ebc_rule_witness: ObEbcRuleTraceWitness<F>,
}

pub trait ObContractsStorageChip<F: Field> {
    fn parse_multi_blocks_contracts_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ObContractsStorageBlockInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (ObMultiBlocksContractsStorageTraceWitness<F>, ObMultiBlocksContractsDigest<F>);

    fn parse_single_block_contracts_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: (Vec<u8>, ObContractsStorageInputAssigned<F>),
        block_header_config: &BlockHeaderConfig,
    ) -> (ObSingleBlockContractsStorageTraceWitness<F>, ObSingleBlockContractsDigest<F>)
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_contract_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: (&AssignedBytes<F>, EthStorageInputAssigned<F>),
    ) -> (ObAccountStorageTraceWitness<F>, ObContractStoragesDigest<F>);

    fn parse_ebc_rule_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        ebc_rule_root_witness: EthStorageTraceWitness<F>,
        proof: MPTProof<F>,
    ) -> ObEbcRuleTraceWitness<F>;

    fn parse_multi_blocks_contracts_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: ObMultiBlocksContractsStorageTraceWitness<F>,
    ) -> ObContractsStoragesTrace<F>;

    fn parse_single_block_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: ObSingleBlockContractsStorageTraceWitness<F>,
    ) -> ObSingleBlockContractsTrace<F>
    where
        Self: EthBlockHeaderChip<F>;

    fn parse_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ObAccountStorageTraceWitness<F>,
    ) -> ObAccountStorageTrace<F>;

    fn parse_ebc_rule_proof_phase1(
        &self,
        ctx: RlcContextPair<F>,
        witness: ObEbcRuleTraceWitness<F>,
    ) -> ObEbcRuleTrace<F>;
}

impl<'chip, F: Field> ObContractsStorageChip<F> for EthChip<'chip, F> {
    fn parse_multi_blocks_contracts_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        input: ObContractsStorageBlockInputAssigned<F>,
        block_header_config: &BlockHeaderConfig,
    ) -> (ObMultiBlocksContractsStorageTraceWitness<F>, ObMultiBlocksContractsDigest<F>) {
        let (witnesses, digests): (
            Vec<ObSingleBlockContractsStorageTraceWitness<F>>,
            Vec<ObSingleBlockContractsDigest<F>>,
        ) = input
            .contract_storage_block
            .into_iter()
            .map(|(block_header, contracts_storage)| {
                self.parse_single_block_contracts_storages_proofs_phase0(
                    thread_pool,
                    keccak,
                    (block_header, contracts_storage),
                    block_header_config,
                )
            })
            .unzip();

        // ebc rule
        let ctx = thread_pool.main(FIRST_PHASE);
        let ebc_rule_root_witness = witnesses[0].contracts_witnesses[0].storage_witness[0].clone();
        let ebc_rule_trace_witness = self.parse_ebc_rule_proof_phase0(
            ctx,
            keccak,
            ebc_rule_root_witness,
            input.ebc_rules_pfs,
        );

        (
            ObMultiBlocksContractsStorageTraceWitness {
                multi_blocks_contracts_witness: witnesses,
                ebc_rule_witness: ebc_rule_trace_witness.clone(),
            },
            ObMultiBlocksContractsDigest {
                multi_blocks_contracts_digest: digests,
                ebc_rule_hash: ebc_rule_trace_witness.ebc_rule_hash,
            },
        )
    }

    fn parse_single_block_contracts_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        (block_header, contracts_storage): (Vec<u8>, ObContractsStorageInputAssigned<F>),
        block_header_config: &BlockHeaderConfig,
    ) -> (ObSingleBlockContractsStorageTraceWitness<F>, ObSingleBlockContractsDigest<F>)
    where
        Self: EthBlockHeaderChip<F>,
    {
        let ctx = thread_pool.main(FIRST_PHASE);
        let mut block_header = block_header;
        block_header.resize(block_header_config.block_header_rlp_max_bytes, 0);
        let block_witness =
            self.decompose_block_header_phase0(ctx, keccak, &block_header, block_header_config);

        let state_root = &block_witness.get_state_root().field_cells;
        let block_hash_hi_lo = bytes_be_to_u128(ctx, self.gate(), &block_witness.block_hash);

        let block_num_bytes = &block_witness.get_number().field_cells;
        let block_num_len = block_witness.get_number().field_len;
        let block_number =
            bytes_be_var_to_fixed(ctx, self.gate(), block_num_bytes, block_num_len, 4);
        let block_number = bytes_be_to_uint(ctx, self.gate(), &block_number, 4);

        let (contracts_witnesses, contracts_digests): (Vec<_>, Vec<_>) = contracts_storage
            .contracts_storage
            .into_iter()
            .map(|contract_storage| {
                self.parse_contract_storages_proofs_phase0(
                    thread_pool,
                    keccak,
                    (state_root, contract_storage),
                )
            })
            .unzip();

        let mut contracts_address = vec![];
        let mut slots_values = vec![];
        let mut address_is_empty = vec![];
        let mut slots_is_empty = vec![];
        for digest in contracts_digests {
            contracts_address.push(digest.address);
            slots_values.extend(digest.slots_values);
            address_is_empty.push(digest.address_is_empty);
            slots_is_empty.push(digest.slot_is_empty);
        }

        (
            ObSingleBlockContractsStorageTraceWitness { contracts_witnesses, block_witness },
            ObSingleBlockContractsDigest {
                block_hash: block_hash_hi_lo.try_into().unwrap(),
                block_number,
                contracts_address,
                slots_values,
                address_is_empty,
                slots_is_empty,
            },
        )
    }

    fn parse_contract_storages_proofs_phase0(
        &self,
        thread_pool: &mut GateThreadBuilder<F>,
        keccak: &mut KeccakChip<F>,
        (state_root, storage): (&AssignedBytes<F>, EthStorageInputAssigned<F>),
    ) -> (ObAccountStorageTraceWitness<F>, ObContractStoragesDigest<F>) {
        let ctx = thread_pool.main(FIRST_PHASE);
        // verify account + storage proof
        let addr_bytes = uint_to_bytes_be(ctx, self.range(), &storage.address, 20);
        let (slots, storage_pfs): (Vec<_>, Vec<_>) = storage
            .storage_pfs
            .into_iter()
            .map(|(slot, storage_pf)| {
                let slot_bytes =
                    slot.iter().map(|u128| uint_to_bytes_be(ctx, self.range(), u128, 16)).concat();
                (slot, (slot_bytes, storage_pf))
            })
            .unzip();
        // drop ctx
        let (acct_witness, storage_witness) = self.parse_eip1186_proofs_phase0(
            thread_pool,
            keccak,
            state_root,
            addr_bytes,
            storage.acct_pf,
            storage_pfs,
        );

        let ctx = thread_pool.main(FIRST_PHASE);
        let slots_values = slots
            .into_iter()
            .zip(storage_witness.iter())
            .map(|(slot, witness)| {
                // get value as U256 from RLP decoding, convert to H256, then to hi-lo
                let value_bytes = &witness.value_witness.witness.field_cells;
                let value_len = witness.value_witness.witness.field_len.clone();
                let value_bytes =
                    bytes_be_var_to_fixed(ctx, self.gate(), value_bytes, value_len, 32);
                let value: [_; 2] =
                    bytes_be_to_u128(ctx, self.gate(), &value_bytes).try_into().unwrap();
                (slot, value)
            })
            .collect_vec();

        let digest = ObContractStoragesDigest {
            address: storage.address,
            slots_values,
            address_is_empty: acct_witness.mpt_witness.slot_is_empty.clone(),
            slot_is_empty: storage_witness
                .iter()
                .map(|witness| witness.mpt_witness.slot_is_empty)
                .collect_vec(),
        };

        (ObAccountStorageTraceWitness { acct_witness, storage_witness }, digest)
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

        let hash_idx = keccak.keccak_var_len(
            ctx,
            self.range(),
            proof.value_bytes.to_vec(), // depends on the value of the constant EBC_RULE_PROOF_VALUE_MAX_BYTE_LEN = 140,
            None,
            ebc_rule_rlp_witness.rlp_len.clone(),
            0,
        );

        let hash_bytes = keccak.var_len_queries[hash_idx].output_assigned.clone();
        let hash: [_; 2] = bytes_be_to_u128(ctx, self.gate(), &hash_bytes).try_into().unwrap();

        let ebc_rule_mpt_witness = self.parse_mpt_inclusion_phase0(ctx, keccak, proof);

        ObEbcRuleTraceWitness { ebc_rule_rlp_witness, ebc_rule_mpt_witness, ebc_rule_hash: hash }
    }

    fn parse_multi_blocks_contracts_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: ObMultiBlocksContractsStorageTraceWitness<F>,
    ) -> ObContractsStoragesTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let contracts_storages_trace = witnesses
            .multi_blocks_contracts_witness
            .into_iter()
            .map(|witnesses| {
                self.parse_single_block_contract_storages_proofs_phase1(thread_pool, witnesses)
            })
            .collect();
        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();
        let ebc_trace =
            self.parse_ebc_rule_proof_phase1((ctx_gate, ctx_rlc), witnesses.ebc_rule_witness);
        ObContractsStoragesTrace { contracts_trace: contracts_storages_trace, ebc_trace }
    }

    fn parse_single_block_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witnesses: ObSingleBlockContractsStorageTraceWitness<F>,
    ) -> ObSingleBlockContractsTrace<F>
    where
        Self: EthBlockHeaderChip<F>,
    {
        let block_trace =
            self.decompose_block_header_phase1(thread_pool.rlc_ctx_pair(), witnesses.block_witness);

        let contracts_storages_trace = witnesses
            .contracts_witnesses
            .into_iter()
            .map(|contract_storage_trace_witness| {
                self.parse_contract_storages_proofs_phase1(
                    thread_pool,
                    contract_storage_trace_witness,
                )
            })
            .collect();

        let (ctx_gate, ctx_rlc) = thread_pool.rlc_ctx_pair();

        // pre-load rlc cache so later parallelization is deterministic
        self.rlc().load_rlc_cache((ctx_gate, ctx_rlc), self.gate(), CACHE_BITS);

        ObSingleBlockContractsTrace { block_trace, contracts_storages_trace }
    }

    fn parse_contract_storages_proofs_phase1(
        &self,
        thread_pool: &mut RlcThreadBuilder<F>,
        witness: ObAccountStorageTraceWitness<F>,
    ) -> ObAccountStorageTrace<F> {
        let (acct_trace, storage_trace) = self.parse_eip1186_proofs_phase1(
            thread_pool,
            (witness.acct_witness, witness.storage_witness),
        );

        ObAccountStorageTrace { acct_trace, storage_trace }
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
