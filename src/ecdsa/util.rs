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

pub fn recover_tx_info(t: &Transaction) -> (Signature, Bytes, H256, PublicKey) {
    let signature = Signature { r: t.r, s: t.s, v: t.v.as_u64() };
    let typed_tx: TypedTransaction = t.into();
    let msg_hash = typed_tx.sighash();
    let public_key = recover_public_key(&signature.clone(), msg_hash);
    (signature, typed_tx.rlp(), msg_hash, public_key)
}

fn recover_public_key<M>(s: &Signature, message: M) -> PublicKey
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

    public_key
}
