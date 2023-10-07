use std::{
    env::set_var,
    fs,
    ops::Range,
    path::{Path, PathBuf},
};

use ark_std::{end_timer, start_timer};
use ethers_core::types::Bytes;
use halo2_base::{gates::builder::CircuitBuilderStage, utils::fs::gen_srs};
use hex::FromHex;
use itertools::Itertools;
use snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, write_calldata},
    gen_pk,
    halo2::{
        aggregation::{AggregationCircuit, AggregationConfigParams},
        gen_snark_shplonk,
    },
    CircuitExt, SHPLONK,
};

use crate::arbitration::helper::TransactionTask;
use crate::track_block::util::TrackBlockConstructor;
use crate::transaction::ethereum::util::{get_eth_transaction_circuit, TransactionConstructor};
use crate::{
    rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder},
    storage::{
        tests::get_test_circuit as get_test_storage_circuit, EthBlockStorageCircuit,
        StorageConfigParams,
    },
    track_block::{util::get_eth_track_block_circuit, EthTrackBlockCircuit},
    transaction::ethereum::{
        tests::get_test_circuit as get_test_ethereum_tx_circuit, EthBlockTransactionCircuit,
    },
    util::{
        circuit::custom_gen_evm_verifier_shplonk,
        scheduler::{arbitration_scheduler::ArbitrationScheduler, Scheduler},
        EthConfigParams,
    },
    EthPreCircuit, EthereumNetwork, Network,
};

use super::helper::{ArbitrationTask, ETHBlockTrackTask};

fn test_get_storage_circuit(network: Network, block_number: u32) -> EthBlockStorageCircuit {
    get_test_storage_circuit(network, block_number)
}

fn test_get_ethereum_tx_circuit(
    transaction_index: u32,
    transaction_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    network: Network,
) -> EthBlockTransactionCircuit {
    get_test_ethereum_tx_circuit(transaction_index, transaction_rlp, merkle_proof, network)
}

fn test_get_block_track_circuit(constructor: TrackBlockConstructor) -> EthTrackBlockCircuit {
    get_eth_track_block_circuit(constructor)
}

fn test_scheduler(network: Network) -> ArbitrationScheduler {
    ArbitrationScheduler::new(
        network,
        false,
        false,
        PathBuf::from("configs/arbitration/"),
        PathBuf::from("data/arbitration/"),
    )
}

#[test]
pub fn test_arbitration_scheduler_block_track_task() {
    let network = Network::Ethereum(EthereumNetwork::Mainnet);
    let block_number_interval =
        vec![(17113952..17113954).collect_vec(), (17113955..17113957).collect_vec()];
    let constructor_one =
        TrackBlockConstructor { block_number_interval: block_number_interval[0].clone(), network };
    let constructor_two =
        TrackBlockConstructor { block_number_interval: block_number_interval[1].clone(), network };

    let scheduler = test_scheduler(network);
    let _task = ETHBlockTrackTask {
        input: test_get_block_track_circuit(constructor_one.clone()),
        network: Network::Ethereum(EthereumNetwork::Mainnet),
        tasks_len: 2,
        task_width: 2,
        constructor: vec![constructor_one, constructor_two],
    };

    let snark = scheduler.get_snark(ArbitrationTask::ETHBlockTrack(_task));
    println!("snark instances_num {:?}  instances {:?}", snark.instances[0].len(), snark.instances);
}

#[test]
pub fn test_arbitration_scheduler_transaction_task() {
    let network = Network::Ethereum(EthereumNetwork::Mainnet);

    let block_number = 0xeee246;
    let transaction_index = 53;
    let transaction_rlp = Vec::from_hex("02f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();

    let proof_one_str = Vec::from_hex("f8b1a0d2b8a354f61d3d7a1fa0de1af78958094a3eed9374756cea377879edb0bc7422a0460779b6e7622dfc26dc9d87a5660dfd08a7338323d287f7d370ac1a474fbd53a03d77ff4a636303a1415da7085256e5041f36d7d0c9b97cfd6ba394b4f66e5f31a0d7e1a6ff03b18783bc4de36fd8c2122907e56de404c6eac2084432f4dacf231680808080a0e3263af8ff4c48d1b5bf85931a69ad8d759df6ef7b6507fbdb87a62547edd0238080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f8f1a0587596c6e4da70eb8697f12d5e59733bbebd14c07bbcf56aac4adbbeb903bca1a04a06b1a1d3b0ab9609f6a7776b43b730955020ac3f90bd43dff0018c895983dca04a31b06be6094943ff2f96afb092f04fd3e28a1b8138e5792187ae563ae62ff0a010ad65155d44082ba6f9c15328f24b19c8a9f42e94489d362b5e1250017e2ec0a01d76ade4e7af7470fd3d019b55ef0f49747d2bf487acd541cd3b0bfae4e2aa97a02553d6d7e11c7b21ecee4c4b7ae341e615a29efe6fb3e16de022817986a6b987a0891ad5f0c0f5ef449173e8516c8ae143edfb9ef629ce40d5346630cd7c73605e80808080808080808080").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f87920b87602f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];

    let transaction_pf_max_depth = merkle_proof.len().clone();

    let constructor = TransactionConstructor {
        block_number,
        transaction_index,
        transaction_rlp,
        merkle_proof,
        transaction_pf_max_depth,
        network,
    };

    let scheduler = test_scheduler(network);
    let _task = TransactionTask {
        input: get_eth_transaction_circuit(constructor.clone()),
        tasks_len: 2,
        task_width: 1,
        constructor: vec![constructor],
    };

    scheduler.get_snark(ArbitrationTask::Transaction(_task));
}


#[test]
pub fn test_arbitration_circuit() {
    let transaction_param = EthConfigParams::from_path("configs/arbitration/ethereum_tx.json");
    let storage_param = StorageConfigParams::from_path("configs/arbitration/storage.json");
    let evm_param = AggregationConfigParams::from_path("configs/arbitration/arbitration_evm.json");

    let (eth_tx_snark, eth_tx_proof_time) = {
        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&transaction_param).unwrap());
        let transaction_index = 53;
        let transaction_rlp = Vec::from_hex("02f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();

        let proof_one_str = Vec::from_hex("f8b1a0d2b8a354f61d3d7a1fa0de1af78958094a3eed9374756cea377879edb0bc7422a0460779b6e7622dfc26dc9d87a5660dfd08a7338323d287f7d370ac1a474fbd53a03d77ff4a636303a1415da7085256e5041f36d7d0c9b97cfd6ba394b4f66e5f31a0d7e1a6ff03b18783bc4de36fd8c2122907e56de404c6eac2084432f4dacf231680808080a0e3263af8ff4c48d1b5bf85931a69ad8d759df6ef7b6507fbdb87a62547edd0238080808080808080").unwrap();
        let proof_one = Bytes::from(proof_one_str);

        let proof_two_str = Vec::from_hex("f8f1a0587596c6e4da70eb8697f12d5e59733bbebd14c07bbcf56aac4adbbeb903bca1a04a06b1a1d3b0ab9609f6a7776b43b730955020ac3f90bd43dff0018c895983dca04a31b06be6094943ff2f96afb092f04fd3e28a1b8138e5792187ae563ae62ff0a010ad65155d44082ba6f9c15328f24b19c8a9f42e94489d362b5e1250017e2ec0a01d76ade4e7af7470fd3d019b55ef0f49747d2bf487acd541cd3b0bfae4e2aa97a02553d6d7e11c7b21ecee4c4b7ae341e615a29efe6fb3e16de022817986a6b987a0891ad5f0c0f5ef449173e8516c8ae143edfb9ef629ce40d5346630cd7c73605e80808080808080808080").unwrap();
        let proof_two = Bytes::from(proof_two_str);

        let proof_three_str = Vec::from_hex("f87920b87602f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();
        let proof_three = Bytes::from(proof_three_str);

        let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];

        let k = transaction_param.degree;
        let input = test_get_ethereum_tx_circuit(
            transaction_index,
            transaction_rlp,
            merkle_proof,
            Network::Ethereum(EthereumNetwork::Mainnet),
        );
        let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);
        let manual_break_points = RlcThreadBreakPoints {
            gate: [
                [
                    8108, 8109, 8108, 8110, 8109, 8108, 8109, 8109, 8110, 8110, 8110, 8110, 8108,
                    8110, 8110, 8110, 8109, 8108, 8108, 8110, 8109, 8109, 8110, 8110, 8110, 8109,
                    8110, 8108, 8108, 8108, 8109, 8110, 8110, 8110, 8110,
                ]
                .into(),
                [
                    8110, 8108, 8108, 8108, 8108, 8109, 8110, 8108, 8109, 8109, 8108, 8108, 8110,
                    8109, 8108, 8109, 8110, 8109,
                ]
                .into(),
                [].into(),
            ]
            .into(),
            rlc: [8109, 8110].into(),
        };
        // let manual_break_points = RlcThreadBreakPoints {
        //     gate: [[].into(), [].into(), [].into()].into(),
        //     rlc: [8109, 8110].into()
        // };
        let break_points_t = circuit.circuit.break_points.take();
        let params = gen_srs(k);
        let pk = gen_pk(&params, &circuit, None);
        let break_points = circuit.circuit.break_points.take();
        let storage_proof_time = start_timer!(|| "Ethereum Tx Proof SHPLONK");
        let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
        let snark = gen_snark_shplonk(
            &params,
            &pk,
            circuit,
            None::<&str>,
        );
        end_timer!(storage_proof_time);
        (snark, storage_proof_time)
    };

    let (storage_snark, storage_proof_time) = {
        set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&storage_param).unwrap());
        let k = storage_param.degree;
        let input = test_get_storage_circuit(Network::Ethereum(EthereumNetwork::Goerli), 9731724);
        let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);
        let params = gen_srs(k);
        let pk = gen_pk(&params, &circuit, None);
        let break_points = circuit.circuit.break_points.take();
        println!("break_points {:?}", break_points);
        let manual_break_points = RlcThreadBreakPoints {
            gate: [
                [262034, 262034, 262034, 262032, 262032].into(),
                [262034, 262034].into(),
                [].into(),
            ]
            .into(),
            rlc: [].into(),
        };
        let storage_proof_time = start_timer!(|| "Storage Proof SHPLONK");
        let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
        let snark = gen_snark_shplonk(
            &params,
            &pk,
            circuit,
            None::<&str>,
        );
        end_timer!(storage_proof_time);
        (snark, storage_proof_time)
    };

    let k = evm_param.degree;
    let params = gen_srs(k);
    set_var("LOOKUP_BITS", evm_param.lookup_bits.to_string());
    let evm_circuit = AggregationCircuit::public::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        None,
        evm_param.lookup_bits,
        &params,
        // vec![eth_tx_snark.clone(), storage_snark.clone()],
        vec![eth_tx_snark.clone()],
        false,
    );
    evm_circuit.config(k, Some(10));
    let pk = gen_pk(&params, &evm_circuit, None);
    let break_points = evm_circuit.break_points();
    println!("arbitration evm break_points {:?}", break_points);

    let instances = evm_circuit.instances();
    let evm_proof_time = start_timer!(|| "EVM Proof SHPLONK");
    let pf_circuit = AggregationCircuit::public::<SHPLONK>(
        CircuitBuilderStage::Prover,
        Some(break_points),
        evm_param.lookup_bits,
        &params,
        vec![eth_tx_snark.clone(), storage_snark.clone()],
        // vec![eth_tx_snark.clone()],
        false,
    );
    let proof = gen_evm_proof_shplonk(&params, &pk, pf_circuit, instances.clone());
    end_timer!(evm_proof_time);
    fs::create_dir_all("data/transaction").unwrap();
    write_calldata(&instances, &proof, Path::new("data/arbitration/test.calldata")).unwrap();

    let deployment_code = custom_gen_evm_verifier_shplonk(
        &params,
        pk.get_vk(),
        &evm_circuit,
        Some(Path::new("data/arbitration/test.yul")),
    );

    // this verifies proof in EVM and outputs gas cost (if successful)
    evm_verify(deployment_code, instances, proof);
}
