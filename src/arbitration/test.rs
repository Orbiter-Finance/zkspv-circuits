use std::str::FromStr;
use std::{
    env::set_var,
    fs,
    ops::Range,
    path::{Path, PathBuf},
};

use ark_std::{end_timer, start_timer};
use ethers_core::types::{Address, Bytes, H256};
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
    CircuitExt, Snark, SHPLONK,
};

use crate::arbitration::circuit_types::FinalAssemblyFinality;
use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::arbitration::helper::{
    FinalAssemblyConstructor, FinalAssemblyTask, MDCStateTask, TransactionTask,
};
use crate::storage::contract_storage::util::{
    get_contracts_storage_circuit, EbcRuleParams, MultiBlocksContractsStorageConstructor,
    ObContractStorageConstructor, SingleBlockContractsStorageConstructor,
};
use crate::storage::util::get_mdc_storage_circuit;
use crate::track_block::util::TrackBlockConstructor;
use crate::transaction::ethereum::util::{get_eth_transaction_circuit, TransactionConstructor};
use crate::transaction::EthTransactionType;
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
    block_number: u32,
    transaction_index: u32,
    transaction_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    network: Network,
) -> EthBlockTransactionCircuit {
    get_test_ethereum_tx_circuit(
        block_number,
        transaction_index,
        transaction_rlp,
        merkle_proof,
        network,
    )
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
        PathBuf::from("cache_data/arbitration/"),
    )
}

fn test_block_track_task(network: Network) -> ETHBlockTrackTask {
    let constructor =
        TrackBlockConstructor { blocks_number: vec![17113954, 17113964, 17113974], network };
    ETHBlockTrackTask {
        input: test_get_block_track_circuit(constructor.clone()),
        network: Network::Ethereum(EthereumNetwork::Mainnet),
        tasks_len: 1,
        task_width: 3,
        constructor: vec![constructor],
    }
}

#[test]
pub fn test_arbitration_scheduler_block_track_task() {
    let network = Network::Ethereum(EthereumNetwork::Mainnet);
    let scheduler = test_scheduler(network);
    let _task = test_block_track_task(network);
    scheduler.get_snark(ArbitrationTask::ETHBlockTrack(_task));
}

fn test_dest_transaction_task(network: Network) -> TransactionTask {
    let block_number = 0x977c48;
    let transaction_index = 59u32;
    let transaction_rlp = Vec::from_hex("02f86e058201de81ee82018482520894afcfbb382b28dae47b76224f24ee29be2c82364887b1a2bc2ec507d580c001a07dbeed6812afe6778a00ca965e5e36e154a822151f3c3475d0e33e73bee08ef3a044a72b69eb5e9288249ea5dbc39ad4e396cf484587c8cfdcca8f7263b67be786").unwrap();

    let proof_one_str = Vec::from_hex("f90131a0151c8cf1278c7fca62d39e4b347346540401354e979b7595fb425312b39e3d4fa014c8582849542b2dce952e47f438acf59de04c22ff189283c9cf29864dff13f7a0817d2a2f4d25d77f921db43c79d9813b90e90013b8c1b12ee33076a7fb105d41a00836fd65f37c3c828aa12f7c19f0c6c3de28107010a20eb3aad2667e556d3380a0bc08a936913199d1858a69f808e4deb66eef0b7820b12922ecc707f1e988fe1da0dd54c95a08aaede4420ab836cb3f03ba4f13fb4a7a16b766f08285d2b751201da00dd5c5a8bf06fcceac59f9457f3c4e6f6c11498e3e076a0d2c7d86593fab5e9ca0d6ff42c4d0256ca59b52a4dd16f354582cd29d57c37ed7f16670710b72c3a2dea0c0c938027a20e1afc0f9949fe37b59b359e036c125ecb2a4b07d2c619cb8b2048080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f90211a0c896b300c7acf9a8d8ce84765404e48d56a441182168dcde070490277eaedd54a0067217c7664eda4f4c1d2515df14ff92658ccee494e509807f3dd20063d48711a0cff2086c779b6b788b75c7ae25b1e8157177a8200d26e23b951372bd46ca5b83a03e6d27bafa999f78fa5c503d44dc5fc2017663ce6704d65181ab90b00a5b846aa05c8f679633d1a242fcc851aebd3cb86c251900bcaf841abd01e0f14ac2e43e9fa02a18805a27bb5822fca88400f3b9cfbe8c630cf258d00f6821e73ea344cb5ee3a02a1e4eace8a5d25b42b626a314909cfa92f8b3eee90c8f072c5ee343e8b6b0efa06d630d767a4f3b61313ff01b03032431b70848ac3978cb4263004495edb4ca81a05dd63dc2bd09a79312014b31732ceeda8b0e0b94d14db7458eb38dd27396b606a08e1c4507b2be01e4643b952379708e45be4f2710ce3daac5030fd4692aa60ac9a0849cd93d71d46253768afd9b3bf783e1b7345ae2fc7a7a54c57b118b585f35f9a00786cb529901a496db5b0ca8321d3e5fa7cfef46aff79319f35958571918bbd0a09eb475f21cc6c3075f4ffc3a942927e8495959b16dfaa175adc73cbcc0979f01a070de1e13ed354cc124b32d8fc2ac43b6020596b969fe422657d7e27c98f358a1a0a8822e31528e3db97d5a2aff8d16f92fc609b62d7a73458f0d6467c78cf371fea052b1fadd6fa13b95b0d530232f9b7d7ce6be4774b0a4277c3a831e8fec8ac7db80").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f87420b87102f86e058201de81ee82018482520894afcfbb382b28dae47b76224f24ee29be2c82364887b1a2bc2ec507d580c001a07dbeed6812afe6778a00ca965e5e36e154a822151f3c3475d0e33e73bee08ef3a044a72b69eb5e9288249ea5dbc39ad4e396cf484587c8cfdcca8f7263b67be786").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];
    let constructor = TransactionConstructor {
        block_number,
        transaction_index: Option::from(transaction_index),
        transaction_index_bytes: None,
        transaction_rlp,
        merkle_proof,
        transaction_pf_max_depth: 8,
        network,
    };

    TransactionTask {
        input: get_eth_transaction_circuit(constructor.clone()),
        tx_type: EthTransactionType::DynamicFeeTxType,
        tasks_len: 1,
        constructor: vec![constructor],
        aggregated: true,
    }
}

fn test_transaction_task(network: Network) -> TransactionTask {
    let block_number = 0x977bfd;
    let transaction_index = 149u32;
    let transaction_rlp = Vec::from_hex("02f86d058201dd3882010982520894afcfbb382b28dae47b76224f24ee29be2c82364887b1a2bc2ec507d580c080a0085e88a81b800e8d867768472efc86db5d26402a10074b89f7aa1abbbcbdf2a4a00b0861009d0c37f6f1621d477319f34ea0c28fae63cb0fc1cf43b033b86c7e9e").unwrap();

    let proof_one_str = Vec::from_hex("f90131a09afcc93de43c2ff5dccf3efa30f1837b9d69681f4ab25534f45665645f555f32a05c1011ef873396a88da4c12ae3fea0cb8de884d082754af30127485a3eab4342a014e3381f48de513184a3e6aaa4be6441ff2ce8d403adefd003a09ecb252b8c98a0b49d761a7064f30760305b7afed1b70f1adaf7b36ab6bed0b77cfb561e2566a8a0de5d00864da19345f8ee4d5eb076dec4ff7410a42315be5b92165e87daca293ba00bb4d126ba4fa18d713f2a7e264bda0c6aaa27c962c8a4fc8b873164268eeb81a069acde74ea3765b9511238733471d39dcf23f2fb810133c367d45779526576c4a0c06b171d6b563a784c04bb647e71282fed477270443f3f54b76225a551e49606a09fbad5e61d65ea365b45377d6929e9f89706d2830b9e4532a48a8aa3a47d62278080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f851a091abac49c8185fc365985481efe69d1f730b557473320da678da6aba65568caaa0edb764568fc40a66cce8dcead360fe7d5858a4762964895ac16aef7312b645f9808080808080808080808080808080").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f8518080808080808080a0c4b18899a8b5db893f96a9475afe8c336f4bbe8b59daa803e759a91f7fa9b800a0e6bb498a386c9162e8b7c7504ff05453bce0e8b76af082a6b2deb808f07bfca880808080808080").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let proof_four_str = Vec::from_hex("f8d1a092ccb8b6c4edbd8c30c67a85c5b0efd0f2ed16aafdc5cf3aa7006cd295ae2786a0489cb2a2288b598b19b0b0e9f2dc34467eee72568dbfc71b20cd04555eb872f5a00e4632669cdaee14c6658ca80f334243003e8205eee3179f4ef95458b9a3b449a01f4e3e9b4b4bd1dcba9123828b06c816bcc1e626e589df25ee974024fbf5af28a0c81d758d2f59bc5fe1a1ff8d538b655bbc7d90b41ccceb3e7387d3b0cdec67bca085ace6b1a41b7a5e7fec3e20c28ef933034e822e6b068ab0f2d09f44d06d79d78080808080808080808080").unwrap();
    let proof_four = Bytes::from(proof_four_str);

    let proof_five_str = Vec::from_hex("f87320b87002f86d058201dd3882010982520894afcfbb382b28dae47b76224f24ee29be2c82364887b1a2bc2ec507d580c080a0085e88a81b800e8d867768472efc86db5d26402a10074b89f7aa1abbbcbdf2a4a00b0861009d0c37f6f1621d477319f34ea0c28fae63cb0fc1cf43b033b86c7e9e").unwrap();
    let proof_five = Bytes::from(proof_five_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three, proof_four, proof_five];

    let constructor = TransactionConstructor {
        block_number,
        transaction_index: Option::from(transaction_index),
        transaction_index_bytes: None,
        transaction_rlp,
        merkle_proof,
        transaction_pf_max_depth: 8,
        network,
    };

    TransactionTask {
        input: get_eth_transaction_circuit(constructor.clone()),
        tx_type: EthTransactionType::DynamicFeeTxType,
        tasks_len: 1,
        constructor: vec![constructor],
        aggregated: false,
    }
}

#[test]
pub fn test_arbitration_scheduler_source_transaction_task() {
    let network = Network::Ethereum(EthereumNetwork::Goerli);
    let scheduler = test_scheduler(network);
    let _task = test_dest_transaction_task(network);
    scheduler.get_snark(ArbitrationTask::Transaction(_task));
}

#[test]
pub fn test_arbitration_scheduler_dest_transaction_task() {
    let network = Network::Ethereum(EthereumNetwork::Goerli);
    let scheduler = test_scheduler(network);
    let _task = test_transaction_task(network);
    scheduler.get_snark(ArbitrationTask::Transaction(_task));
}

fn test_mdc_task(network: Network) -> MDCStateTask {
    let block_number = 9927633;

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
    let slots = vec![version_slot, enable_time_slot];
    let single_block_contract_storage_constructor = ObContractStorageConstructor {
        contract_address: addr,
        slots,
        acct_pf_max_depth: 9,
        storage_pf_max_depth: 8,
    };
    let single_block_contracts_storage_constructor = SingleBlockContractsStorageConstructor {
        block_number,
        block_contracts_storage: vec![
            single_block_contract_storage_constructor.clone(),
            single_block_contract_storage_constructor,
        ],
    };
    let constructor = MultiBlocksContractsStorageConstructor {
        blocks_contracts_storage: vec![
            single_block_contracts_storage_constructor.clone(),
            single_block_contracts_storage_constructor,
        ],
        ebc_rule_params,
        network,
    };

    MDCStateTask {
        input: get_contracts_storage_circuit(constructor.clone()),
        single_block_include_contracts: 2,
        multi_blocks_number: 2,
        constructor: vec![constructor],
        aggregated: false,
    }
}
#[test]
pub fn test_arbitration_scheduler_mdc_task() {
    let network = Network::Ethereum(EthereumNetwork::Goerli);
    let scheduler = test_scheduler(network);
    let _task = test_mdc_task(network);
    scheduler.get_snark(ArbitrationTask::MDCState(_task));
}

// #[test]
// pub fn test_arbitration_scheduler_source_final_task() {
//     let network = Network::Ethereum(EthereumNetwork::Mainnet);

//     let block_network = Network::Ethereum(EthereumNetwork::Mainnet);

//     let transaction_network = Network::Ethereum(EthereumNetwork::Mainnet);

//     let mdc_network = Network::Ethereum(EthereumNetwork::Goerli);

//     let scheduler = test_scheduler(network);

//     let transaction_task = test_transaction_task(transaction_network);

//     let eth_block_track_task = test_block_track_task(block_network);

//     let mdc_state_task = test_mdc_task(mdc_network);

//     let constructor =
//         FinalAssemblyConstructor { transaction_task, eth_block_track_task, mdc_state_task };

//     let _task = FinalAssemblyTask { round: 3, network, constructor };
//     scheduler.get_calldata(ArbitrationTask::Final(_task), true);
// }

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
            0xeee246,
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
        let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
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
        let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
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
        vec![eth_tx_snark.clone(), storage_snark.clone()],
        // vec![eth_tx_snark.clone()],
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
        // vec![eth_tx_snark.clone(), storage_snark.clone()],
        vec![eth_tx_snark.clone()],
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
