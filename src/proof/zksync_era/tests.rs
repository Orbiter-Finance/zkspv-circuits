use std::env::set_var;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::str::FromStr;
use ark_std::{end_timer, start_timer};
use ethers_core::types::{H256, TxHash};

use halo2_base::{
    halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    utils::fs::gen_srs,
};
use halo2_base::gates::builder::CircuitBuilderStage;
use rand_core::OsRng;
use snark_verifier_sdk::{CircuitExt, gen_pk, SHPLONK};
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, write_calldata};
use snark_verifier_sdk::halo2::aggregation::{AggregationCircuit, AggregationConfigParams};
use snark_verifier_sdk::halo2::gen_snark_shplonk;
use crate::{Network, ZkSyncEraNetwork};
use crate::transaction::zksync_era::now::ZkSyncBlockTransactionCircuit;
use crate::util::helpers::get_provider;
use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    rlp::builder::RlcThreadBuilder,
    util::EthConfigParams,
};
use crate::util::circuit::custom_gen_evm_verifier_shplonk;

fn get_test_circuit(
    tx_hash: H256,
    network: Network,
) -> ZkSyncBlockTransactionCircuit {
    let provider = get_provider(&network);
    ZkSyncBlockTransactionCircuit::from_provider(&provider, tx_hash, network)
}

#[test]
pub fn test_zksync_proof() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/zksync_era_proof.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());

    let k = params.degree;
    let network = Network::ZkSync(ZkSyncEraNetwork::Mainnet);
    let tx_hash = TxHash::from_str("0xa040db0769aeaacd51816aedf3036e16a30b815f12d4b89bb6a943d16f34cf45").unwrap();

    let input = get_test_circuit(tx_hash, network);
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);

    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
pub fn test_zksync_proof_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/zksync_era_proof.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());

    let k = params.degree;
    let network = Network::ZkSync(ZkSyncEraNetwork::Mainnet);
    let tx_hash = TxHash::from_str("0xa040db0769aeaacd51816aedf3036e16a30b815f12d4b89bb6a943d16f34cf45").unwrap();

    let input = get_test_circuit(tx_hash, network);

    let circuit = input.clone().create_circuit::<Fr>(RlcThreadBuilder::keygen(), None);

    let instance = circuit.instance();
    let param = gen_srs(k);
    let vk = keygen_vk(&param, &circuit)?;
    let pk = keygen_pk(&param, vk, &circuit)?;
    let break_points = circuit.circuit.break_points.take();

    // create a proof
    let proof_time = start_timer!(|| "create proof SHPLONK");
    let phase0_time = start_timer!(|| "phase 0 synthesize");
    let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
    end_timer!(phase0_time);
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&param, &pk, &[circuit], &[&[&instance]], OsRng, &mut transcript)?;
    let proof = transcript.finalize();
    end_timer!(proof_time);

    let verify_time = start_timer!(|| "Verify time");
    let verifier_params = param.verifier_params();
    let strategy = SingleStrategy::new(&param);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[&instance]], &mut transcript)
        .unwrap();
    end_timer!(verify_time);
    Ok(())
}


#[test]
#[cfg(feature = "evm")]
pub fn test_zksync_proof_keygen_evm() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/zksync_era_proof.json");
    let evm_params_file = File::open("configs/zksync/evm.json").unwrap();
    let evm_params_reader = BufReader::new(evm_params_file);
    let evm_params: AggregationConfigParams =
        serde_json::from_reader(evm_params_reader).unwrap();

    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());

    let (storage_snark, storage_proof_time) = {
        let k = params.degree;
        let network = Network::ZkSync(ZkSyncEraNetwork::Mainnet);
        let tx_hash = TxHash::from_str("0xa040db0769aeaacd51816aedf3036e16a30b815f12d4b89bb6a943d16f34cf45").unwrap();
        let input = get_test_circuit(tx_hash, network);
        let circuit = input.clone().create_circuit::<Fr>(RlcThreadBuilder::keygen(), None);
        let params = gen_srs(k);
        let pk = gen_pk(&params, &circuit, None);
        let break_points = circuit.circuit.break_points.take();
        let storage_proof_time = start_timer!(|| "Storage Proof SHPLONK");
        let circuit =
            input.create_circuit::<Fr>(RlcThreadBuilder::prover(), Some(break_points));
        let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
        end_timer!(storage_proof_time);
        (snark, storage_proof_time)
    };

    let k = evm_params.degree;
    let params = gen_srs(k);
    set_var("LOOKUP_BITS", evm_params.lookup_bits.to_string());
    let evm_circuit = AggregationCircuit::public::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        None,
        evm_params.lookup_bits,
        &params,
        vec![storage_snark.clone()],
        false,
    );
    evm_circuit.config(k, Some(10));
    let pk = gen_pk(&params, &evm_circuit, None);
    let break_points = evm_circuit.break_points();

    let instances = evm_circuit.instances();
    let evm_proof_time = start_timer!(|| "EVM Proof SHPLONK");
    let pf_circuit = AggregationCircuit::public::<SHPLONK>(
        CircuitBuilderStage::Prover,
        Some(break_points),
        evm_params.lookup_bits,
        &params,
        vec![storage_snark],
        false,
    );
    let proof = gen_evm_proof_shplonk(&params, &pk, pf_circuit, instances.clone());
    end_timer!(evm_proof_time);
    fs::create_dir_all("data/storage").unwrap();
    write_calldata(&instances, &proof, Path::new("data/storage/zksync.calldata")).unwrap();

    let deployment_code = custom_gen_evm_verifier_shplonk(
        &params,
        pk.get_vk(),
        &evm_circuit,
        Some(Path::new("data/storage/zksync.yul")),
    );

    // this verifies proof in EVM and outputs gas cost (if successful)
    evm_verify(deployment_code, instances, proof);

    Ok(())
}