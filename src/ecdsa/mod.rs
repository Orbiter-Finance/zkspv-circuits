pub mod util;

use crate::ecdsa::util::recover_tx_info;
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::*,
    poly::commitment::ParamsProver,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use crate::halo2_proofs::{
    poly::kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use crate::mpt::AssignedBytes;
use crate::rlp::rlc::FIRST_PHASE;
use crate::util::helpers::load_bytes;
use crate::{EthChip, EthCircuitBuilder, EthPreCircuit, ETH_LOOKUP_BITS};
use ark_std::{end_timer, start_timer};
use ethers_core::k256::elliptic_curve::consts::U32;
use ethers_core::k256::elliptic_curve::generic_array::GenericArray;
use ethers_core::k256::elliptic_curve::group::GroupEncoding as ethers_GroupEncoding;
use ethers_core::k256::elliptic_curve::sec1::ToEncodedPoint;
use ethers_core::k256::elliptic_curve::weierstrass::add;
use ethers_core::k256::{
    ecdsa::{Signature as K256Signature, VerifyingKey},
    EncodedPoint, PublicKey, Secp256k1,
};
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{Bytes, RecoveryMessage, Signature, Transaction, H256};
use ethers_core::utils::{hash_message, keccak256};
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};
use halo2_base::gates::{GateInstructions, RangeChip};
use halo2_base::halo2_proofs::halo2curves::group::{Curve, GroupEncoding};
use halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Compressed;
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::safe_types::ScalarField;
use halo2_base::{AssignedValue, Context};
use hex::{FromHex, ToHex};
use itertools::Itertools;
use rlp::{Decodable, Rlp};
use serde::{Deserialize, Serialize};
use snark_verifier::loader::halo2::halo2_ecc::ecc::ecdsa::ecdsa_verify_no_pubkey_check;
use snark_verifier::loader::halo2::halo2_ecc::ecc::EccChip;
use snark_verifier::loader::halo2::halo2_ecc::fields::{FieldChip, FpStrategy, PrimeField};
use snark_verifier::loader::halo2::halo2_ecc::secp256k1::{FpChip, FqChip};
use std::fs::File;
use std::hash::Hasher;
use zkevm_keccak::util::eth_types::Field;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

pub struct EcdsaChip<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub fq_chip: &'chip FqChip<'chip, F>,
}

impl<'chip, F: PrimeField> EcdsaChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, fq_chip: &'chip FqChip<F>) -> Self {
        Self { fp_chip, fq_chip }
    }

    pub fn ecdsa_pubkey_verify(
        &self,
        ctx: &mut Context<F>,
        ecdsa_input_assigned: EthEcdsaInputAssigned<F>,
    ) -> AssignedValue<F> {
        let [m, r, s] =
            [ecdsa_input_assigned.message_hash, ecdsa_input_assigned.r, ecdsa_input_assigned.s]
                .map(|x| self.fq_chip.load_private(ctx, x));

        let ecc_chip = EccChip::<F, FpChip<F>>::new(&self.fp_chip);
        let pk = ecc_chip.load_private_unchecked(
            ctx,
            (ecdsa_input_assigned.public_key.x, ecdsa_input_assigned.public_key.y),
        );
        ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
            &ecc_chip, ctx, pk, r, s, m, 4, 4,
        )
    }
}

#[derive(Clone, Debug)]
pub struct EthEcdsaInput {
    pub signature: Signature,
    pub message: Bytes,
    pub message_hash: H256,
    pub public_key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct EthEcdsaInputAssigned<F: PrimeField> {
    pub r: Fq,
    pub s: Fq,
    pub message_hash: Fq,
    pub public_key: Secp256k1Affine,
    pub public_key_bytes: AssignedBytes<F>,
}

impl EthEcdsaInput {
    pub fn assign<F: Field>(self, ctx: &mut Context<F>) -> EthEcdsaInputAssigned<F> {
        let public_key_point = self.public_key.to_encoded_point(false);
        let public_key_point_x = hex::encode(public_key_point.x().unwrap());
        let public_key_point_y = hex::encode(public_key_point.y().unwrap());

        let mut p_x = Vec::from_hex(public_key_point_x).unwrap();
        p_x.reverse();
        let p_x = Fp::from_bytes_le(p_x.as_slice());
        let mut p_y = Vec::from_hex(public_key_point_y).unwrap();
        p_y.reverse();
        let p_y = Fp::from_bytes_le(p_y.as_slice());

        let public_key = Secp256k1Affine::from_xy(p_x, p_y).unwrap();

        let mut m_q = self.message_hash.0.clone();
        m_q.reverse();
        let message_hash = Fq::from_bytes(&m_q).unwrap();

        let r_q = self.signature.r.0.clone();
        let r = Fq::from_raw(r_q);
        let s_q = self.signature.s.0.clone();
        let s = Fq::from_raw(s_q);

        let p_x_bytes: [u8; 32] = public_key.x.to_bytes();
        let mut p_x_bytes = p_x_bytes.to_vec();
        p_x_bytes.reverse();
        let p_y_bytes: [u8; 32] = public_key.y.to_bytes();
        let mut p_y_bytes = p_y_bytes.to_vec();
        p_y_bytes.reverse();
        let public_key_bytes = load_bytes(ctx, [p_x_bytes, p_y_bytes].concat().as_slice());

        EthEcdsaInputAssigned { r, s, message_hash, public_key, public_key_bytes }
    }
}

#[derive(Clone, Debug)]
pub struct EthEcdsaCircuit {
    pub inputs: EthEcdsaInput,
}

impl EthEcdsaCircuit {
    pub fn new(inputs: Vec<u8>) -> Self {
        let transaction = Transaction::decode(&Rlp::new(&inputs)).unwrap();
        let (signature, message, message_hash, public_key) = recover_tx_info(&transaction);
        Self { inputs: EthEcdsaInput { signature, message, message_hash, public_key } }
    }
    fn create_circuit(
        self,
        params: CircuitParams,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
    ) -> RangeCircuitBuilder<Fr> {
        std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
        let mut builder = match stage {
            CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
            CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
            CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
        };

        let range = RangeChip::default(params.lookup_bits);
        let fp_chip = FpChip::new(&range, params.limb_bits, params.num_limbs);
        let fq_chip = FqChip::new(&range, params.limb_bits, params.num_limbs);

        let ctx = builder.main(FIRST_PHASE);
        let input = self.inputs.assign(ctx);
        let ecdsa_chip = EcdsaChip::new(&fp_chip, &fq_chip);

        let res = ecdsa_chip.ecdsa_pubkey_verify(ctx, input);
        {
            let ctx = builder.main(FIRST_PHASE);
            range.gate.assert_is_const(ctx, &res, &Fr::one());
        }

        let circuit = match stage {
            CircuitBuilderStage::Mock => {
                builder.config(params.degree as usize, Some(20));
                RangeCircuitBuilder::mock(builder)
            }
            CircuitBuilderStage::Keygen => {
                builder.config(params.degree as usize, Some(20));
                RangeCircuitBuilder::keygen(builder)
            }
            CircuitBuilderStage::Prover => {
                RangeCircuitBuilder::prover(builder, break_points.unwrap())
            }
        };
        circuit
    }
}

#[test]
fn test_ecdsa_circuit() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let transaction_rlp = Vec::from_hex("02f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();

    let input = EthEcdsaCircuit::new(transaction_rlp);
    let circuit = input.create_circuit(params, CircuitBuilderStage::Mock, None);
    // let circuit = real_ecdsa_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
