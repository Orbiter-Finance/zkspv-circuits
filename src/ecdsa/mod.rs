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
use ethers_core::k256::elliptic_curve::group::GroupEncoding as ethers_GroupEncoding;
use ethers_core::k256::elliptic_curve::sec1::ToEncodedPoint;
use ethers_core::k256::{
    ecdsa::{Signature as K256Signature, VerifyingKey},
    EncodedPoint, PublicKey, Secp256k1,
};
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{Bytes, RecoveryMessage, Signature, Transaction, H256};
use ethers_core::utils::hash_message;
use ff::Field;
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::group::{Curve, GroupEncoding};
use halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Compressed;
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::safe_types::ScalarField;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};
use halo2_base::Context;
use hex::{FromHex, ToHex};
use rand_core::OsRng;
use rlp::{Decodable, Rlp};
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

fn real_ecdsa_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let (r, s, msg_hash, pubkey) = ecdsa_example();

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
fn test_ecdsa() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = real_ecdsa_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

pub fn recover_from(t: &Transaction) -> (Signature, Bytes, H256, PublicKey) {
    let signature = Signature { r: t.r, s: t.s, v: t.v.as_u64() };
    let typed_tx: TypedTransaction = t.into();
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

fn ecdsa_example() -> (Fq, Fq, Fq, Secp256k1Affine) {
    use halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1 as Secp256k1_halo2;

    fn mod_n(x: Fp) -> Fq {
        let mut x_repr = [0u8; 32];
        x_repr.copy_from_slice(x.to_repr().as_ref());
        let mut x_bytes = [0u8; 64];
        x_bytes[..32].copy_from_slice(&x_repr[..]);
        Fq::from_bytes_wide(&x_bytes)
    }

    // transaction
    let transaction_rlp = Vec::from_hex("02f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();
    let transaction = Transaction::decode(&Rlp::new(&transaction_rlp)).unwrap();

    let (sig, message, message_hash, public_key) = recover_from(&transaction);

    let public_key_point = public_key.to_encoded_point(false);
    let public_key_point_x = hex::encode(public_key_point.x().unwrap());
    let public_key_point_y = hex::encode(public_key_point.y().unwrap());
    //println!("public_key_point_x:{:?}", public_key_point_x); //  c0457b76bc1a1a1f40a9ddb30ff7ddc9cdbc4b2745c61f9e47d3f9b650dd3aaf
    //println!("public_key_point_y:{:?}", public_key_point_y); //  288506d5d79d1ad3e1cb0091cce20bf81f0f44309d645cf8475894d949b29c45

    let mut p_x = Vec::from_hex(public_key_point_x).unwrap();
    p_x.reverse();
    let p_x = Fp::from_bytes_le(p_x.as_slice());
    let mut p_y = Vec::from_hex(public_key_point_y).unwrap();
    p_y.reverse();
    let p_y = Fp::from_bytes_le(p_y.as_slice());

    // let g = Secp256k1_halo2::generator();

    let pk = Secp256k1Affine::from_xy(p_x, p_y).unwrap();

    let mut m_q = message_hash.0.clone();
    m_q.reverse();
    let msg_hash = Fq::from_bytes(&m_q).unwrap();

    let r_q = sig.r.0.clone();
    let r = Fq::from_raw(r_q);
    let s_q = sig.s.0.clone();
    let s = Fq::from_raw(s_q);

    // Verify
    // let s_inv = s.invert().unwrap();
    // let u_1 = msg_hash * s_inv;
    // let u_2 = r * s_inv;
    //
    // let v_1 = g * u_1;
    // let v_2 = pk * u_2;
    //
    // let r_point = (v_1 + v_2).to_affine().coordinates().unwrap();
    // let x_candidate = r_point.x();
    // let r_candidate = mod_n(*x_candidate);
    // assert_eq!(r, r_candidate);

    (r, s, msg_hash, pk)
}
