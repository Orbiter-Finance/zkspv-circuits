mod tests;
pub mod util;

use crate::block_header::{get_block_header_config, BlockHeaderConfig};
use crate::ecdsa::EcdsaChip;
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::providers::{get_receipt_input, get_transaction_input};
use crate::receipt::{EthBlockReceiptChip, EthBlockReceiptInput};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::rlc::FIRST_PHASE;
use crate::rlp::RlpChip;
use crate::transaction::ethereum::{EthBlockTransactionChip, EthBlockTransactionInput};
use crate::transaction_receipt::util::TransactionReceiptConstructor;
use crate::{
    EthChip, EthCircuitBuilder, EthPreCircuit, ETH_LIMB_BITS, ETH_LOOKUP_BITS, ETH_NUM_LIMBS,
};
use ethers_providers::{Http, Provider};
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier::loader::halo2::halo2_ecc::secp256k1::{FpChip, FqChip};
use std::cell::RefCell;

#[derive(Clone, Debug)]
pub struct TransactionReceiptCircuit {
    pub eth_transaction_input: EthBlockTransactionInput,
    pub eth_receipt_input: EthBlockReceiptInput,
    pub block_header_config: BlockHeaderConfig,
}

impl TransactionReceiptCircuit {
    pub fn from_provider(
        provider: &Provider<Http>,
        constructor: TransactionReceiptConstructor,
    ) -> Self {
        let eth_transaction_input = get_transaction_input(
            provider,
            constructor.eth_transaction.transaction_hash,
            constructor.eth_transaction.transaction_index_bytes,
            constructor.eth_transaction.transaction_rlp.unwrap(),
            constructor.eth_transaction.merkle_proof.unwrap(),
            constructor.eth_transaction.transaction_pf_max_depth.unwrap(),
        );
        let eth_receipt_input = get_receipt_input(
            provider,
            constructor.eth_receipt.transaction_hash,
            constructor.eth_receipt.receipt_index_bytes,
            constructor.eth_receipt.receipt_rlp,
            constructor.eth_receipt.merkle_proof,
            constructor.eth_receipt.receipt_pf_max_depth,
        );
        let block_header_config = get_block_header_config(&constructor.eth_transaction.network);
        Self { eth_transaction_input, eth_receipt_input, block_header_config }
    }
}

impl EthPreCircuit for TransactionReceiptCircuit {
    fn create(
        self,
        mut builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let range = RangeChip::default(ETH_LOOKUP_BITS);
        let eth = EthChip::new(RlpChip::new(&range, None), None);
        let mut keccak = KeccakChip::default();
        let fp_chip = FpChip::new(&range, ETH_LIMB_BITS, ETH_NUM_LIMBS);
        let fq_chip = FqChip::new(&range, ETH_LIMB_BITS, ETH_NUM_LIMBS);
        let ecdsa = EcdsaChip::new(&fp_chip, &fq_chip);

        // ================= FIRST PHASE ================
        let ctx = builder.gate_builder.main(FIRST_PHASE);
        let eth_transaction_input_assigned = self.eth_transaction_input.assign(ctx);
        let eth_receipt_input_assigned = self.eth_receipt_input.assign(ctx);
        let (eth_transaction_witness, eth_transaction_digest) = eth
            .parse_transaction_proof_from_block_phase0(
                &mut builder.gate_builder,
                &mut keccak,
                &ecdsa,
                eth_transaction_input_assigned,
                &self.block_header_config,
            );

        let (eth_receipt_witness, eth_receipt_digest) = eth.parse_receipt_proof_from_block_phase0(
            &mut builder.gate_builder,
            &mut keccak,
            eth_receipt_input_assigned,
            &self.block_header_config,
        );

        let assigned_instances = eth_transaction_digest
            .block_hash
            .into_iter()
            .chain(eth_transaction_digest.transaction_field.hash)
            .chain([
                eth_transaction_digest.transaction_field.chain_id,
                eth_transaction_digest.index,
                eth_transaction_digest.transaction_field.from,
                eth_transaction_digest.transaction_field.to,
                eth_transaction_digest.transaction_field.token,
                eth_transaction_digest.transaction_field.amount,
                eth_transaction_digest.transaction_field.nonce,
                eth_transaction_digest.transaction_field.time_stamp,
                eth_transaction_digest.transaction_field.dest_transfer_address,
                eth_transaction_digest.transaction_field.dest_transfer_token,
            ])
            .collect_vec();

        {
            let ctx = builder.gate_builder.main(FIRST_PHASE);
            range.gate.assert_is_const(
                ctx,
                &eth_transaction_digest.transaction_is_empty,
                &Fr::zero(),
            );
            range.gate.assert_is_const(ctx, &eth_receipt_digest.receipt_is_empty, &Fr::zero());

            // Check whether the index of transaction and receipt are consistent
            ctx.constrain_equal(&eth_transaction_digest.index, &eth_receipt_digest.index);

            // Check whether the block hash of transaction and receipt are consistent
            for (transaction_block_hash, receipt_block_hash) in
                eth_transaction_digest.block_hash.iter().zip(eth_receipt_digest.block_hash.iter())
            {
                ctx.constrain_equal(transaction_block_hash, receipt_block_hash);
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
                let eth = EthChip::new(rlp, Some(keccak_rlcs));
                eth.parse_transaction_proof_from_block_phase1(builder, eth_transaction_witness);
                eth.parse_receipt_proof_from_block_phase1(builder, eth_receipt_witness);
            },
        )
    }
}
