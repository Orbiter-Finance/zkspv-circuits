mod tests;

use ethers_core::k256::U256;
use ethers_core::types::H256;
use halo2_base::{AssignedValue, Context};
use zkevm_keccak::util::eth_types::Field;
use crate::{EthChip, Network};
use crate::keccak::KeccakChip;
use crate::mpt::{AssignedBytes, MPTFixedKeyProof, MPTFixedKeyProofWitness};
use crate::rlp::RlpFieldTraceWitness;

pub struct EthBlockTransactionTraceWitness<F: Field> {
    value_witness: RlpFieldTraceWitness<F>,
    mpt_witness: MPTFixedKeyProofWitness<F>,
}

pub trait EthBlockTransactionChip<F: Field> {
    fn parse_transaction_proof_phase0(
        &self,
        ctx: &mut Context<F>,
        keccak: &mut KeccakChip<F>,
        transactions_root_bytes: &[AssignedValue<F>],
        transaction_index_bytes: AssignedBytes<F>,
        proof: MPTFixedKeyProof<F>,
    ) -> EthBlockTransactionTraceWitness<F>;
}

impl<'chip, F: Field> EthBlockTransactionChip<F> for EthChip<'chip, F> {
    fn parse_transaction_proof_phase0(&self, ctx: &mut Context<F>, keccak: &mut KeccakChip<F>, transactions_root_bytes: &[AssignedValue<F>], transaction_index_bytes: AssignedBytes<F>, proof: MPTFixedKeyProof<F>) -> EthBlockTransactionTraceWitness<F> {
        // assert!(32,proof.key_bytes.len()); transaction_index_bytes len ≈ 1- ♾+

        // check MPT root is transactions_root
        for (pf_root, root) in proof.root_hash_bytes.iter().zip(transactions_root_bytes.iter()) {
            ctx.constrain_equal(pf_root, root);
        }

        // parse slot value
        let value_witness =
            self.rlp().decompose_rlp_field_phase0(ctx, proof.value_bytes.clone(), 32);
        // check MPT inclusion
        let mpt_witness = self.parse_mpt_inclusion_fixed_key_phase0(ctx, keccak, proof);
        EthBlockTransactionTraceWitness { value_witness, mpt_witness }
    }
}

#[derive(Clone,Debug)]
pub struct EthTransactionInput{
    pub transaction_index: U256,
    pub transaction_proofs: Vec<H256>
}

#[derive(Clone,Debug)]
pub struct EthBlockTransactionInput{
    pub transactions_root:H256,
    pub transaction:EthTransactionInput
}


#[derive(Clone,Debug)]
pub struct EthBlockTransactionCircuit{
    pub inputs:EthBlockTransactionInput,
    pub network: Network
}