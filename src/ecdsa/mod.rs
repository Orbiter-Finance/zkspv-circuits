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
use ark_std::{end_timer, start_timer};
use ethers_core::k256::elliptic_curve::consts::U32;
use ethers_core::k256::elliptic_curve::generic_array::GenericArray;
use ethers_core::k256::elliptic_curve::group::GroupEncoding;
use ethers_core::k256::elliptic_curve::sec1::ToEncodedPoint;
use ethers_core::k256::{
    ecdsa::{Signature as K256Signature, VerifyingKey},
    EncodedPoint, PublicKey, Secp256k1,
};
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{Bytes, RecoveryMessage, Signature, Transaction, H256};
use ethers_core::utils::hash_message;
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};
use halo2_base::gates::RangeChip;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};
use halo2_base::Context;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use snark_verifier::loader::halo2::halo2_ecc::ecc::ecdsa::ecdsa_verify_no_pubkey_check;
use snark_verifier::loader::halo2::halo2_ecc::ecc::EccChip;
use snark_verifier::loader::halo2::halo2_ecc::fields::{FieldChip, FpStrategy, PrimeField};
use snark_verifier::loader::halo2::halo2_ecc::secp256k1::{FpChip, FqChip};
use std::fs::File;

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

fn ecdsa_test<F: PrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    r: Fq,
    s: Fq,
    msghash: Fq,
    pk: Secp256k1Affine,
) {
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let [m, r, s] = [msghash, r, s].map(|x| fq_chip.load_private(ctx, x));

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.load_private_unchecked(ctx, (pk.x, pk.y));
    // test ECDSA
    let res = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    println!("res:{:?}", &res);
    assert_eq!(res.value(), &F::one());
}

fn random_ecdsa_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let pubkey = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);
    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msg_hash + (r * sk));

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    ecdsa_test(builder.main(0), params, r, s, msg_hash, pubkey);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

#[test]
fn test_secp256k1_ecdsa() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_ecdsa_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

pub fn recover_from(t: &Transaction) -> (Signature, Bytes, H256, PublicKey) {
    let signature = Signature { r: t.r, s: t.s, v: t.v.as_u64() };
    let typed_tx: TypedTransaction = t.into();
    // signature.recover(typed_tx.sighash());
    let msgHash = typed_tx.sighash();
    let public_key = recover(&signature.clone(), msgHash);
    (signature, typed_tx.rlp(), msgHash, public_key)
}

pub fn recover<M>(s: &Signature, message: M) -> PublicKey
where
    M: Into<RecoveryMessage>,
{
    let message = message.into();
    let message_hash = match message {
        RecoveryMessage::Data(ref message) => hash_message(message),
        RecoveryMessage::Hash(hash) => hash,
    };
    let recovery_id = s.recovery_id().unwrap();
    let recoverable_sig = {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        s.r.to_big_endian(&mut r_bytes);
        s.s.to_big_endian(&mut s_bytes);
        let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&r_bytes);
        let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&s_bytes);
        K256Signature::from_scalars(*gar, *gas).unwrap()
    };

    let verify_key =
        VerifyingKey::recover_from_prehash(message_hash.as_ref(), &recoverable_sig, recovery_id)
            .unwrap();

    let public_key = PublicKey::from(&verify_key);
    // let public_key = public_key.to_encoded_point(/* compress = */ false);
    // debug_assert_eq!(public_key[0], 0x04);

    public_key
}
