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

use crate::config::contract::get_mdc_config;
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
    let mut addr = Default::default();
    let mdc_config = get_mdc_config();
    let provider = get_provider(&network);

    match network {
        Network::Ethereum(EthereumNetwork::Mainnet) => {
            addr = mdc_config.mainnet;
        }
        Network::Ethereum(EthereumNetwork::Goerli) => {
            addr = mdc_config.goerli;
        }
        _ => {
            panic!("no match network Type! {:?}", network)
        }
    }

    // ebc_rule_mpt
    let ebc_rule_key =
        H256::from_str("0x3c88efaf9c3d1286548d2deb92050254b42314cf32d32c85e8f641e116d445ac")
            .unwrap();
    let ebc_rule_root =
        H256::from_str("0xd5fe6597c1607bb7c648c8b50e605ff2cd84a52e3e5ecb1e6381dc29e5ee963b")
            .unwrap(); // should be consistent with the value corresponding to the slot
    let ebc_rule_value = Vec::from_hex("f83c058201a4010180808701c6bf52634c3587027ca57357c0198701c6bf526342718702d79883d23d09865af31082cb80865af3108626e00102211c1b1e").unwrap();

    let proof_one_bytes = Vec::from_hex("f851808080a054400bf453b955313a021e9e2c4ca85a8fc549642c13bd15743a74ccad8f6359808080808080808080a03df71b77eaaac25d64355678b33182a08f195c23a25eadafcc891c814bc3eda7808080").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);
    let proof_two_bytes = Vec::from_hex("f851808080808080a0b2848dbcfb2a125ed37d204fb2482d7584d52b2576e1a08a806c03963cd673bf8080808080a08af38922ea2dde162982a604c549b1a62eea1e524c22fcae14b5260204576d1c80808080").unwrap();
    let proof_two = Bytes::from(proof_two_bytes);
    let proof_three_bytes = Vec::from_hex("f861a02088efaf9c3d1286548d2deb92050254b42314cf32d32c85e8f641e116d445acb83ef83c058201a4010180808701c6bf52634c3587027ca57357c0198701c6bf526342718702d79883d23d09865af31082cb80865af3108626e00102211c1b1e").unwrap();
    let proof_three = Bytes::from(proof_three_bytes);

    let ebc_rule_merkle_proof = vec![proof_one, proof_two, proof_three];
    let ebc_rule_pf_max_depth = ebc_rule_merkle_proof.len().clone();

    let ebc_rule_params = EbcRuleParams {
        ebc_rule_key,
        ebc_rule_root,
        ebc_rule_value,
        ebc_rule_merkle_proof,
        ebc_rule_pf_max_depth,
    };

    // slots:
    addr = "0x3671625AD4CD14b6A4C2fb2697292E84DD3c1F10".parse().unwrap(); // for test
    let mapping_position = 0;
    let root_slot_position = 0;
    let version_slot_position = 1;

    let root_slot = calculate_mk_address_struct(addr, mapping_position, root_slot_position);
    let version_slot = calculate_mk_address_struct(addr, mapping_position, version_slot_position);
    let slots = vec![root_slot, version_slot];
    let constructor = StorageConstructor {
        block_number,
        address: addr,
        slots,
        acct_pf_max_depth: 8,
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

    let input = get_test_circuit(Network::Ethereum(EthereumNetwork::Goerli), 9731724);
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
