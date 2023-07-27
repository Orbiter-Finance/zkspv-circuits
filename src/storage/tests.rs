use std::{
    env::set_var,
    fs::File,
    io::{BufReader, Write},
};

use ark_std::{end_timer, start_timer};
use ethers_core::utils::keccak256;
use halo2_base::utils::fs::gen_srs;
use test_log::test;
use circuit_derive;
use serde::{Deserialize, Serialize};

use crate::{ArbitrumNetwork, EthereumNetwork, halo2_proofs::{
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
}, util::scheduler::Scheduler};
use crate::block_header::helper::CircuitRouter::ForEvm;
use crate::util::helpers::get_provider;

use super::*;

fn get_test_circuit(network: Network, num_slots: usize) -> EthBlockStorageCircuit {

    assert!(num_slots <= 10);
    let provider = get_provider(&network);
    let mut addr = Default::default();
    let mut block_number = 0;
    match network {
        Network::Ethereum(EthereumNetwork::Mainnet) => {
            // cryptopunks
            addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>().unwrap();
            block_number = 16356350;
        }
        Network::Ethereum(EthereumNetwork::Goerli) => {
            addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>().unwrap();
            block_number = 0x713d54;
        }
        Network::Arbitrum(ArbitrumNetwork::Mainnet)=>{
            block_number  = 0x82e239;
        }
        Network::Arbitrum(ArbitrumNetwork::Goerli)=>{
            block_number  = 0x82e239;
        }
        _ => {}
    }
    // For only occupied slots:
    let slot_nums = vec![0u64, 1u64, 2u64, 3u64, 6u64, 8u64];
    let mut slots = (0..4)
        .map(|x| {
            let mut bytes = [0u8; 64];
            bytes[31] = x;
            bytes[63] = 10;
            H256::from_slice(&keccak256(bytes))
        })
        .collect::<Vec<_>>();
    slots.extend(slot_nums.iter().map(|x| H256::from_low_u64_be(*x)));
    slots.truncate(num_slots);
    // let slots: Vec<_> = (0..num_slots).map(|x| H256::from_low_u64_be(x as u64)).collect();
    slots.truncate(num_slots);
    EthBlockStorageCircuit::from_provider(&provider, block_number, addr, slots, 8, 8, network)
}

#[test]
pub fn test_mock_single_eip1186() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/storage.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_circuit(Network::Ethereum(EthereumNetwork::Mainnet), 1);
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
        CircuitExt,
        evm::{evm_verify, gen_evm_proof_shplonk, write_calldata},
        gen_pk,
        halo2::{
            aggregation::{AggregationCircuit, AggregationConfigParams},
            gen_snark_shplonk,
        }, SHPLONK,
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
            let input = get_test_circuit(Network::Ethereum(EthereumNetwork::Mainnet), bench_params.1);
            let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);
            let params = gen_srs(k);
            let pk = gen_pk(&params, &circuit, None);
            let break_points = circuit.circuit.break_points.take();
            let storage_proof_time = start_timer!(|| "Storage Proof SHPLONK");
            let circuit =
                input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
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
