use std::str::FromStr;
use std::{
    env::set_var,
    fs::File,
    io::{BufReader, Write},
};

use ark_std::{end_timer, start_timer};
use circuit_derive;
use ethers_core::types::Bytes;
use ethers_core::utils::keccak256;
use halo2_base::utils::fs::gen_srs;
use hex::FromHex;
use serde::{Deserialize, Serialize};
use test_log::test;

use crate::storage::util::EbcRuleParams;
use crate::util::helpers::{calculate_mk_address_struct, get_provider};
use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::*,
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
    util::scheduler::Scheduler,
    ArbitrumNetwork, EthereumNetwork,
};

use super::*;

pub fn get_test_circuit(network: Network, block_number: u32) -> EthBlockStorageCircuit {
    let provider = get_provider(&network);

    // ebc_rule_mpt
    let ebc_rule_key =
        H256::from_str("0xb824d67a08c69bc4f694666c7088b5d8eb3151c09000db345a9759f46dc179be")
            .unwrap();
    let ebc_rule_root =
        H256::from_str("0x407857a3d36724da1c9af7cf6cadaa4599f7c2499eda48eace754961c75fbaff")
            .unwrap(); // should be consistent with the value corresponding to the slot
    let ebc_rule_value = Vec::from_hex("f841058308274f010180808701c6bf52634c358809b6e64a8ecbf5e18701c6bf52634005880b1a2bc2ec503d0987038d7ea51bf30087038d7ea53d84c00102211c1b1e").unwrap();

    let proof_one_bytes = Vec::from_hex("f867a120b824d67a08c69bc4f694666c7088b5d8eb3151c09000db345a9759f46dc179beb843f841058308274f010180808701c6bf52634c358809b6e64a8ecbf5e18701c6bf52634005880b1a2bc2ec503d0987038d7ea51bf30087038d7ea53d84c00102211c1b1e").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);

    let ebc_rule_merkle_proof = vec![proof_one];

    let ebc_rule_params = EbcRuleParams {
        ebc_rule_key,
        ebc_rule_root,
        ebc_rule_value,
        ebc_rule_merkle_proof,
        ebc_rule_pf_max_depth: 8,
    };

    // slots:
    let addr = "0x5A295a98bD9FCa8784D98c98f222B7BA52367470".parse().unwrap(); // for test

    let root_slot =
        H256::from_str("0xbb01b056691692273b8d0c6bed43fbc90e57d25c4eb695038e7b6a6c4a7b5b4d")
            .unwrap();
    let version_slot =
        H256::from_str("0xbb01b056691692273b8d0c6bed43fbc90e57d25c4eb695038e7b6a6c4a7b5b4e")
            .unwrap();
    let enable_time_slot =
        H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let slots = vec![root_slot, version_slot, enable_time_slot];
    let constructor = StorageConstructor {
        block_number,
        address: addr,
        slots,
        acct_pf_max_depth: 9,
        storage_pf_max_depth: 8,
        ebc_rule_params,
        network,
    };
    EthBlockStorageCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_mdc_storage() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/storage.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_circuit(Network::Ethereum(EthereumNetwork::Goerli), 9927633);
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BenchParams(EthConfigParams, usize); // (params, num_slots)

#[test]
#[cfg(feature = "evm")]
pub fn bench_evm_eip1186() -> Result<(), Box<dyn std::error::Error>> {
    use crate::util::circuit::custom_gen_evm_verifier_shplonk;
    use halo2_base::gates::builder::CircuitBuilderStage;
    use snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk, write_calldata},
        gen_pk,
        halo2::{
            aggregation::{AggregationCircuit, AggregationConfigParams},
            gen_snark_shplonk,
        },
        CircuitExt, SHPLONK,
    };
    use std::{fs, path::Path};
    let bench_params_file = File::open("configs/bench/storage.json").unwrap();
    let evm_params_file = File::open("configs/bench/storage_evm.json").unwrap();
    fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/storage.csv").unwrap();
    writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,storage_proof_time,evm_proof_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    let bench_params: Vec<BenchParams> = serde_json::from_reader(bench_params_reader).unwrap();
    let evm_params_reader = BufReader::new(evm_params_file);
    let evm_params: Vec<AggregationConfigParams> =
        serde_json::from_reader(evm_params_reader).unwrap();
    for (bench_params, evm_params) in bench_params.iter().zip(evm_params.iter()) {
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.0.degree
        );

        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&bench_params.0).unwrap());

        let (storage_snark, storage_proof_time) = {
            let k = bench_params.0.degree;
            let block_number = bench_params.1 as u32;
            let input = get_test_circuit(Network::Ethereum(EthereumNetwork::Goerli), block_number);
            let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);
            let params = gen_srs(k);
            let pk = gen_pk(&params, &circuit, None);
            let break_points = circuit.circuit.break_points.take();
            let storage_proof_time = start_timer!(|| "Storage Proof SHPLONK");
            let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
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
        write_calldata(&instances, &proof, Path::new("data/storage/test.calldata")).unwrap();

        let deployment_code = custom_gen_evm_verifier_shplonk(
            &params,
            pk.get_vk(),
            &evm_circuit,
            Some(Path::new("data/storage/test.yul")),
        );

        // this verifies proof in EVM and outputs gas cost (if successful)
        evm_verify(deployment_code, instances, proof);

        let keccak_advice = std::env::var("KECCAK_ADVICE_COLUMNS")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<usize>()
            .unwrap();
        let bench_params: EthConfigParams =
            serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap();
        writeln!(
            fs_results,
            "{},{},{},{:?},{:?},{},{:.2}s,{:?}",
            bench_params.degree,
            bench_params.num_rlc_columns
                + bench_params.num_range_advice.iter().sum::<usize>()
                + bench_params.num_lookup_advice.iter().sum::<usize>()
                + keccak_advice,
            bench_params.num_rlc_columns,
            bench_params.num_range_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            storage_proof_time.time.elapsed().as_secs_f64(),
            evm_proof_time.time.elapsed()
        )
        .unwrap();
    }
    Ok(())
}
