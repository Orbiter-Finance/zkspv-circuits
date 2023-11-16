#![allow(unused_imports)]
use super::*;
use crate::{
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::*,
        poly::commitment::{Params, ParamsProver},
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
        transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    },
    rlp::rlc::RlcConfig,
    util::{helpers::get_provider, h256_non_standard_tree_root_and_proof, h256_tree_verify, encode_h256_to_bytes_field, encode_merkle_path_to_field}, Network, EthereumNetwork, providers::get_batch_block_merkle_root,
};
use ark_std::{end_timer, start_timer};
use ethers_core::types::H256;
use ethers_providers::{Provider, Http, Middleware};
use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        range::{RangeConfig, RangeStrategy},
    },
    utils::{fe_to_biguint, fs::gen_srs, value_to_option, ScalarField},
    SKIP_FIRST_PASS,
};
use itertools::{assert_equal, Itertools};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use std::{
    env::{set_var, var},
    fs::{File, self},
    io::{BufRead, BufReader, Write}, str::FromStr,
};
use zkevm_keccak::keccak_packed_multi::get_keccak_capacity;


#[test]
pub fn test_merkle_root_verify() {
    let provider = get_provider(&Network::Ethereum(EthereumNetwork::Mainnet));
    let start_block_num = 17113953;
    let end_block_num = 17114080;

    let leaves = get_block_batch_hashes(&provider, start_block_num.clone(), end_block_num.clone());
    for proof_index in start_block_num..end_block_num+1 {
        let verify_index = proof_index - start_block_num;
        let (proof_root, proof, path) = h256_non_standard_tree_root_and_proof(&leaves, verify_index.clone());
        h256_tree_verify(&proof_root, &leaves[verify_index as usize], &proof, &path);
    }

    let (leaves, root) = get_block_data_hashes_from_json();
    for(leaves, root) in leaves.into_iter().zip(root.into_iter()) {
        for proof_index in 0..leaves.len() {
            let verify_index = proof_index;
            let (proof_root, proof, path) = h256_non_standard_tree_root_and_proof(&leaves, verify_index.clone().try_into().unwrap());
            assert_eq!(root, proof_root);
            h256_tree_verify(&proof_root, &leaves[verify_index as usize], &proof, &path);
        }
    }
}

fn test_keccak_non_standard_merkle_verify_circuit<F: Field>(
    k: u32,
    mut builder: RlcThreadBuilder<F>,
) -> KeccakCircuitBuilder<F, impl FnSynthesize<F>> {
    let prover = builder.witness_gen_only();
    let range = RangeChip::default(8);
    let gate = GateChip::default();
    let keccak = SharedKeccakChip::default();
    let ctx = builder.gate_builder.main(0);

    let (leaves_batch, root_batch) = get_block_data_hashes_from_json();
    let taget_index = leaves_batch[0].len() - 1;
    // let taget_index = 0;
    let ((proof_root, proof, path), target_leaf) = (h256_non_standard_tree_root_and_proof(&leaves_batch[0], taget_index.try_into().unwrap()), leaves_batch[0][taget_index as usize].clone());
    // println!("root: {:?} \n target_leaf: {:?} \n proof: {:?} \n path: {:?}", proof_root,target_leaf, proof, path);
    h256_tree_verify(&proof_root, &target_leaf, &proof, &path);
    assert_eq!(proof_root,root_batch[0]);
    let target_root = ctx.assign_witnesses(encode_h256_to_bytes_field::<F>(proof_root));
    let proof = proof.iter().map(|p| {
        ctx.assign_witnesses(encode_h256_to_bytes_field::<F>(p.clone()))
    }).collect_vec();
    let target_leaf = ctx.assign_witnesses(encode_h256_to_bytes_field::<F>(target_leaf.clone()));
    let path = ctx.assign_witnesses(encode_merkle_path_to_field::<F>(&path));
    keccak.borrow_mut().verify_merkle_proof(ctx, &gate, &target_root, &proof, &target_leaf, &path);
    let circuit = KeccakCircuitBuilder::new(
        builder,
        keccak,
        range,
        None,
        |_: &mut RlcThreadBuilder<F>, _: RlpChip<F>, _: (FixedLenRLCs<F>, VarLenRLCs<F>)| {},
    );
    if !prover {
        let unusable_rows =
            var("UNUSABLE_ROWS").unwrap_or_else(|_| "109".to_string()).parse().unwrap();
        circuit.config(k as usize, Some(unusable_rows));
    }
    circuit
}

fn get_block_data_hashes_from_json() -> (Vec<Vec<H256>>, Vec<H256>) {
    #[derive(Deserialize)]
    struct BatchData {
        batch_1: Vec<String>,
        batch_root_1: String,
        batch_2: Vec<String>,
        batch_root_2: String,
    }

    let data = fs::read_to_string("test_data/block_batch_data.json").unwrap();
    let batch_data: BatchData = serde_json::from_str(&data).unwrap();
    ([
        batch_data.batch_1.into_iter().map(|s| H256::from_str(&s).unwrap()).collect_vec().into_iter().collect_vec(),
        batch_data.batch_2.into_iter().map(|s| H256::from_str(&s).unwrap()).collect_vec().into_iter().collect_vec(),
    ].into_iter().collect_vec(), 
    [
        batch_data.batch_root_1.parse().unwrap(),
        batch_data.batch_root_2.parse().unwrap()
    ].into_iter().collect_vec()
    )
}

fn get_block_batch_hashes(
    provider: &Provider<Http>,
    start_block_num: u32,
    end_block_num: u32,
) -> Vec<H256> {
    let rt = Runtime::new().unwrap();
    assert!(start_block_num <= end_block_num);
    let mut leaves = Vec::with_capacity((end_block_num - start_block_num) as usize);
    for block_num in (start_block_num..=end_block_num) {
        let block = rt.block_on(provider.get_block(block_num as u64)).unwrap().unwrap();
        let block_hash = block.hash.unwrap();
        leaves.push(block_hash);
    }
    leaves
}

fn test_keccak_circuit<F: Field>(
    k: u32,
    mut builder: RlcThreadBuilder<F>,
    inputs: Vec<Vec<u8>>,
    var_len: bool,
) -> KeccakCircuitBuilder<F, impl FnSynthesize<F>> {
    let prover = builder.witness_gen_only();
    let range = RangeChip::default(8);
    let keccak = SharedKeccakChip::default();
    let ctx = builder.gate_builder.main(0);
    let mut rng = StdRng::from_seed([0u8; 32]);
    for (_idx, input) in inputs.into_iter().enumerate() {
        let bytes = input.to_vec();
        let mut bytes_assigned =
            ctx.assign_witnesses(bytes.iter().map(|byte| F::from(*byte as u64)));
        let len =
            if var_len && !bytes.is_empty() { rng.gen_range(0..bytes.len()) } else { bytes.len() };
        for byte in bytes_assigned[len..].iter_mut() {
            *byte = ctx.load_zero();
        }

        let len = ctx.load_witness(F::from(len as u64));

        let _hash = if var_len {
            keccak.borrow_mut().keccak_var_len(ctx, &range, bytes_assigned, Some(bytes), len, 0)
        } else {
            keccak.borrow_mut().keccak_fixed_len(ctx, &range.gate, bytes_assigned, Some(bytes))
        };
    }
    let circuit = KeccakCircuitBuilder::new(
        builder,
        keccak,
        range,
        None,
        |_: &mut RlcThreadBuilder<F>, _: RlpChip<F>, _: (FixedLenRLCs<F>, VarLenRLCs<F>)| {},
    );
    if !prover {
        let unusable_rows =
            var("UNUSABLE_ROWS").unwrap_or_else(|_| "109".to_string()).parse().unwrap();
        circuit.config(k as usize, Some(unusable_rows));
    }
    circuit
}

/// Cmdline: KECCAK_DEGREE=14 RUST_LOG=info cargo test -- --nocapture test_keccak
#[test]
pub fn test_keccak() {
    let _ = env_logger::builder().is_test(true).try_init();

    let k: u32 = var("KECCAK_DEGREE").unwrap_or_else(|_| "14".to_string()).parse().unwrap();
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    let circuit = test_keccak_circuit(k, RlcThreadBuilder::mock(), inputs.clone(), false);
    MockProver::<Fr>::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    println!("Fixed len keccak passed");

    let circuit = test_keccak_circuit(k, RlcThreadBuilder::mock(), inputs, true);
    MockProver::<Fr>::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    println!("Var len keccak passed");
}


#[test]
pub fn test_keccak_non_standard_merkle_verify() {
    let k: u32 = var("KECCAK_DEGREE").unwrap_or_else(|_| "14".to_string()).parse().unwrap();
    let circuit = test_keccak_non_standard_merkle_verify_circuit(k, RlcThreadBuilder::mock());
    MockProver::<Fr>::run(k, &circuit, vec![]).unwrap().assert_satisfied();
    println!("Keccak Non Standard Merkle Verify passed!");
}
#[derive(Serialize, Deserialize)]
pub struct KeccakBenchConfig {
    degree: usize,
    range_advice: Vec<usize>,
    num_rlc: usize,
    unusable_rows: usize,
    rows_per_round: usize,
}

#[test]
fn bench_keccak() {
    let _ = env_logger::builder().is_test(true).try_init();
    let var_len = true;

    let bench_params_file = File::open("configs/bench/keccak.json").unwrap();
    std::fs::create_dir_all("data/bench").unwrap();
    let mut fs_results = File::create("data/bench/keccak.csv").unwrap();
    writeln!(
        fs_results,
        "degree,advice_columns,unusable_rows,rows_per_round,keccak_f/s,num_keccak_f,proof_time,proof_size,verify_time"
    )
        .unwrap();

    let bench_params_reader = BufReader::new(bench_params_file);
    let bench_params: Vec<KeccakBenchConfig> =
        serde_json::from_reader(bench_params_reader).unwrap();
    for bench_params in bench_params {
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );
        let k = bench_params.degree as u32;
        let num_rows = (1 << k) - bench_params.unusable_rows;
        set_var("KECCAK_ROWS", bench_params.rows_per_round.to_string());
        let capacity = get_keccak_capacity(num_rows);
        println!("Performing {capacity} keccak_f permutations");
        let inputs = vec![vec![0; 135]; capacity];
        let circuit = test_keccak_circuit(k, RlcThreadBuilder::keygen(), inputs.clone(), var_len);

        // MockProver::<Fr>::run(k, &circuit, vec![]).unwrap().assert_satisfied();

        let params = gen_srs(k);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();
        let break_points = circuit.break_points.take();

        let inputs = (0..capacity)
            .map(|_| (0..135).map(|_| rand::random::<u8>()).collect_vec())
            .collect_vec();
        // create a proof
        let proof_time = start_timer!(|| "Create proof SHPLONK");
        let circuit = test_keccak_circuit(k, RlcThreadBuilder::prover(), inputs.clone(), var_len);
        *circuit.break_points.borrow_mut() = break_points;
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .unwrap();
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .unwrap();
        end_timer!(verify_time);

        let auto_params: EthConfigParams =
            serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap();
        let keccak_advice = std::env::var("KECCAK_ADVICE_COLUMNS")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<usize>()
            .unwrap();
        writeln!(
            fs_results,
            "{},{},{},{},{:.2},{},{:.2}s,{:?}",
            auto_params.degree,
            auto_params.num_range_advice.iter().sum::<usize>() + keccak_advice + 2,
            var("UNUSABLE_ROWS").unwrap(),
            auto_params.keccak_rows_per_round,
            f64::from(capacity as u32) / proof_time.time.elapsed().as_secs_f64(),
            capacity,
            proof_time.time.elapsed().as_secs_f64(),
            verify_time.time.elapsed()
        )
        .unwrap();
    }
}
