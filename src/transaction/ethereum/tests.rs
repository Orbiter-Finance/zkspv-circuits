use ark_std::{end_timer, start_timer};
use std::env::{set_var, var};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{fs, iter};

use ethers_core::types::Bytes;
use ethers_core::utils::hex::FromHex;
use ff::PrimeField;
use halo2_base::utils::fs::gen_srs;
use itertools::Itertools;
use snark_verifier_sdk::CircuitExt;

use crate::halo2_proofs::dev::MockProver;
use crate::rlp::builder::RlcThreadBuilder;
use crate::transaction::ethereum::util::TransactionConstructor;
use crate::transaction::ethereum::EthBlockTransactionCircuit;
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{EthPreCircuit, EthereumNetwork, Network};

pub fn get_test_circuit(
    block_number: u32,
    transaction_index: u32,
    transaction_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    network: Network,
) -> EthBlockTransactionCircuit {
    let provider = get_provider(&network);
    let constructor = TransactionConstructor {
        block_number,
        transaction_index: Option::from(transaction_index),
        transaction_index_bytes: None,
        transaction_rlp,
        merkle_proof,
        transaction_pf_max_depth: 8,
        network,
    };
    EthBlockTransactionCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_2718_transaction_mpt() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let transaction_index = 1;
    let transaction_rlp = Vec::from_hex("f86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b").unwrap();

    let proof_one_str = Vec::from_hex("f90131a076a89f6eb55cebc7bd5840cdb737b4d5c4cdc7606a94b1c445f7842148752412a03fc1c0d9f1c05d03e4151a6a336bc219a7f50ce562cd7f7a9fa7af79d619ad3ca01a644d23d46541426c501f25245651fbaf7dd9ec37a271bb6085be740275de39a09180e94c8ab99675ba998f53e83f0653a9176297277b0ecea8e85a2f92658da1a0606fb70b7ec78f5782df2098b3ca8abb84edcd53716602fc50fe0701df5837bfa0b3c5fd629a5b3dba81715fbadc5d61fc6f8eb3879af88345b1883002bb56dcb4a083c546f53a64573a88f60be282b9d3f700bebadc1be0a238565a1e1b13e53359a0f62817a8ddca5592e691877da3bd0ce817043511c439857a4a5d87f866a3e59da069bb22ce547922dd6fa51aac9f28d15491060670f65bc312f4b0b29c72e3a7098080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f901f180a02c6872dde49209fa678b257bc46638147347d07ea45a0cc1e7ccdab3a6eb2ddca0707a6691268cb1e4360514141b85380dd62930ce72aa0fb30ece7dfae559ba7da00d0c6f34c6f237d0c5edcd43d6cbd0acfd901c8dd88104ade1709870cd623cdaa0c3a015f441f4013e8c54e0ebd2b7ac42e2fb3fae8ade9da7e1f39841b64d5754a03c5123d2b26b3fd1798f86f07deb8fa3bc363ebdd944d3a467347995199a0575a03e6ce4201598f0485729874a7db824de1a6103feffc0f7e55a6d7f1ecf53fc3ba072ee92a3334b67bd93681ed2e6d1af0f3450bec76fbd70f9710735b2e6866e38a068080a0e43ebb7a507d164c3c43bf1b9d7144e5e949f8cd59480259e345251d4a09c72f08c9ecafdabac19366e7fd1137da807f478d2bd07c7269dee7d85e7686aa0f4135038390a4ffc9adc21387a7ffd7703f64b6faa21eb9f775966f7eec5e903a0930ef1ce37e6af471f4a3df2a4d15d05e52353c9cc14dc833648f5e4393f0aa9a091690279d63333d52897a32689537017867813822d863c0727438335ebe93666a0ca2551fb9de3bf5e6ea98c46bea44a4fcfc9df59df91dfea4cfe4b37e0768797a0a5223397546957bf3a6891cc7d92e50843c4beb427679444be67437329cfab49a06bf38cf8e67b990084e87976b576a68f33fb44de8121eda6f30ca2486f43a61380").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f87420b871f86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];
    let input = get_test_circuit(
        0x82e239,
        transaction_index,
        transaction_rlp,
        merkle_proof,
        Network::Ethereum(EthereumNetwork::Goerli),
    );

    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
pub fn test_1559_source_transaction_mpt() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let transaction_index = 149;
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
    let input = get_test_circuit(
        0x977bfd,
        transaction_index,
        transaction_rlp,
        merkle_proof,
        Network::Ethereum(EthereumNetwork::Goerli),
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
pub fn test_1559_dest_transaction_mpt() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let transaction_index = 59;
    let transaction_rlp = Vec::from_hex("02f86e058201de81ee82018482520894afcfbb382b28dae47b76224f24ee29be2c82364887b1a2bc2ec507d580c001a07dbeed6812afe6778a00ca965e5e36e154a822151f3c3475d0e33e73bee08ef3a044a72b69eb5e9288249ea5dbc39ad4e396cf484587c8cfdcca8f7263b67be786").unwrap();

    let proof_one_str = Vec::from_hex("f90131a0151c8cf1278c7fca62d39e4b347346540401354e979b7595fb425312b39e3d4fa014c8582849542b2dce952e47f438acf59de04c22ff189283c9cf29864dff13f7a0817d2a2f4d25d77f921db43c79d9813b90e90013b8c1b12ee33076a7fb105d41a00836fd65f37c3c828aa12f7c19f0c6c3de28107010a20eb3aad2667e556d3380a0bc08a936913199d1858a69f808e4deb66eef0b7820b12922ecc707f1e988fe1da0dd54c95a08aaede4420ab836cb3f03ba4f13fb4a7a16b766f08285d2b751201da00dd5c5a8bf06fcceac59f9457f3c4e6f6c11498e3e076a0d2c7d86593fab5e9ca0d6ff42c4d0256ca59b52a4dd16f354582cd29d57c37ed7f16670710b72c3a2dea0c0c938027a20e1afc0f9949fe37b59b359e036c125ecb2a4b07d2c619cb8b2048080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f90211a0c896b300c7acf9a8d8ce84765404e48d56a441182168dcde070490277eaedd54a0067217c7664eda4f4c1d2515df14ff92658ccee494e509807f3dd20063d48711a0cff2086c779b6b788b75c7ae25b1e8157177a8200d26e23b951372bd46ca5b83a03e6d27bafa999f78fa5c503d44dc5fc2017663ce6704d65181ab90b00a5b846aa05c8f679633d1a242fcc851aebd3cb86c251900bcaf841abd01e0f14ac2e43e9fa02a18805a27bb5822fca88400f3b9cfbe8c630cf258d00f6821e73ea344cb5ee3a02a1e4eace8a5d25b42b626a314909cfa92f8b3eee90c8f072c5ee343e8b6b0efa06d630d767a4f3b61313ff01b03032431b70848ac3978cb4263004495edb4ca81a05dd63dc2bd09a79312014b31732ceeda8b0e0b94d14db7458eb38dd27396b606a08e1c4507b2be01e4643b952379708e45be4f2710ce3daac5030fd4692aa60ac9a0849cd93d71d46253768afd9b3bf783e1b7345ae2fc7a7a54c57b118b585f35f9a00786cb529901a496db5b0ca8321d3e5fa7cfef46aff79319f35958571918bbd0a09eb475f21cc6c3075f4ffc3a942927e8495959b16dfaa175adc73cbcc0979f01a070de1e13ed354cc124b32d8fc2ac43b6020596b969fe422657d7e27c98f358a1a0a8822e31528e3db97d5a2aff8d16f92fc609b62d7a73458f0d6467c78cf371fea052b1fadd6fa13b95b0d530232f9b7d7ce6be4774b0a4277c3a831e8fec8ac7db80").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f87420b87102f86e058201de81ee82018482520894afcfbb382b28dae47b76224f24ee29be2c82364887b1a2bc2ec507d580c001a07dbeed6812afe6778a00ca965e5e36e154a822151f3c3475d0e33e73bee08ef3a044a72b69eb5e9288249ea5dbc39ad4e396cf484587c8cfdcca8f7263b67be786").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];
    let input = get_test_circuit(
        0x977c48,
        transaction_index,
        transaction_rlp,
        merkle_proof,
        Network::Ethereum(EthereumNetwork::Goerli),
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
#[cfg(feature = "evm")]
pub fn evm_gen_yul() -> Result<(), Box<dyn std::error::Error>> {
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
    let transaction_param = EthConfigParams::from_path("configs/tests/transaction.json");
    let evm_param = AggregationConfigParams::from_path("configs/evm/transaction_evm.json");
    fs::create_dir_all("data/bench")?;
    let mut fs_results = File::create("data/bench/transaction.csv").unwrap();
    writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,storage_proof_time,evm_proof_time")?;

    println!(
        "---------------------- degree = {} ------------------------------",
        transaction_param.degree
    );

    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&transaction_param).unwrap());

    let (storage_snark, storage_proof_time) = {
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
        let input = get_test_circuit(
            0xeee246,
            transaction_index,
            transaction_rlp,
            merkle_proof,
            Network::Ethereum(EthereumNetwork::Mainnet),
        );
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

    let k = evm_param.degree;
    let params = gen_srs(k);
    set_var("LOOKUP_BITS", evm_param.lookup_bits.to_string());
    let evm_circuit = AggregationCircuit::public::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        None,
        evm_param.lookup_bits,
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
        evm_param.lookup_bits,
        &params,
        vec![storage_snark],
        false,
    );
    let proof = gen_evm_proof_shplonk(&params, &pk, pf_circuit, instances.clone());
    end_timer!(evm_proof_time);
    fs::create_dir_all("data/transaction").unwrap();
    write_calldata(&instances, &proof, Path::new("data/transaction/de.calldata")).unwrap();

    let deployment_code = custom_gen_evm_verifier_shplonk(
        &params,
        pk.get_vk(),
        &evm_circuit,
        Some(Path::new("data/transaction/de.yul")),
    );

    let proof_path = Path::new("data/transaction/de.proof");
    encode_proof(&proof, proof_path);
    let instance_path = Path::new("data/transaction/de.instance");
    encode_instance(&instances, instance_path);

    // this verifies proof in EVM and outputs gas cost (if successful)
    // evm_verify(deployment_code, instances, proof);
    //
    // let keccak_advice = var("KECCAK_ADVICE_COLUMNS")
    //     .unwrap_or_else(|_| "0".to_string())
    //     .parse::<usize>()
    //     .unwrap();
    // let transaction_params: EthConfigParams =
    //     serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap();
    // writeln!(
    //     fs_results,
    //     "{},{},{},{:?},{:?},{},{:.2}s,{:?}",
    //     transaction_params.degree,
    //     transaction_params.num_rlc_columns
    //         + transaction_params.num_range_advice.iter().sum::<usize>()
    //         + transaction_params.num_lookup_advice.iter().sum::<usize>()
    //         + keccak_advice,
    //     transaction_params.num_rlc_columns,
    //     transaction_params.num_range_advice,
    //     transaction_params.num_lookup_advice,
    //     transaction_params.num_fixed,
    //     storage_proof_time.time.elapsed().as_secs_f64(),
    //     evm_proof_time.time.elapsed()
    // )
    //     .unwrap();
    Ok(())
}

// #[test]
// #[cfg(feature = "evm")]
// pub fn evm_new_gen_solidity() -> Result<(), Box<dyn std::error::Error>> {
//     use crate::util::circuit::custom_gen_evm_verifier_shplonk;
//     use halo2_base::gates::builder::CircuitBuilderStage;
//     use snark_verifier_sdk::{
//         evm::{evm_verify, gen_evm_proof_shplonk, write_calldata},
//         gen_pk,
//         halo2::{
//             aggregation::{AggregationCircuit, AggregationConfigParams},
//             gen_snark_shplonk,
//         },
//         CircuitExt, SHPLONK,
//     };
//     use std::{fs, path::Path};
//     let transaction_param = EthConfigParams::from_path("configs/tests/transaction.json");
//     let evm_param = AggregationConfigParams::from_path("configs/evm/transaction_evm.json");
//     fs::create_dir_all("data/bench")?;
//     let mut fs_results = File::create("data/bench/transaction.csv").unwrap();
//     writeln!(fs_results, "degree,total_advice,num_rlc_columns,num_advice,num_lookup,num_fixed,storage_proof_time,evm_proof_time")?;
//
//     println!(
//         "---------------------- degree = {} ------------------------------",
//         transaction_param.degree
//     );
//
//     set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&transaction_param).unwrap());
//
//     let (storage_snark, storage_proof_time) = {
//         let transaction_index = 53;
//         let transaction_rlp = Vec::from_hex("02f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();
//
//         let proof_one_str = Vec::from_hex("f8b1a0d2b8a354f61d3d7a1fa0de1af78958094a3eed9374756cea377879edb0bc7422a0460779b6e7622dfc26dc9d87a5660dfd08a7338323d287f7d370ac1a474fbd53a03d77ff4a636303a1415da7085256e5041f36d7d0c9b97cfd6ba394b4f66e5f31a0d7e1a6ff03b18783bc4de36fd8c2122907e56de404c6eac2084432f4dacf231680808080a0e3263af8ff4c48d1b5bf85931a69ad8d759df6ef7b6507fbdb87a62547edd0238080808080808080").unwrap();
//         let proof_one = Bytes::from(proof_one_str);
//
//         let proof_two_str = Vec::from_hex("f8f1a0587596c6e4da70eb8697f12d5e59733bbebd14c07bbcf56aac4adbbeb903bca1a04a06b1a1d3b0ab9609f6a7776b43b730955020ac3f90bd43dff0018c895983dca04a31b06be6094943ff2f96afb092f04fd3e28a1b8138e5792187ae563ae62ff0a010ad65155d44082ba6f9c15328f24b19c8a9f42e94489d362b5e1250017e2ec0a01d76ade4e7af7470fd3d019b55ef0f49747d2bf487acd541cd3b0bfae4e2aa97a02553d6d7e11c7b21ecee4c4b7ae341e615a29efe6fb3e16de022817986a6b987a0891ad5f0c0f5ef449173e8516c8ae143edfb9ef629ce40d5346630cd7c73605e80808080808080808080").unwrap();
//         let proof_two = Bytes::from(proof_two_str);
//
//         let proof_three_str = Vec::from_hex("f87920b87602f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();
//         let proof_three = Bytes::from(proof_three_str);
//
//         let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];
//
//         let k = transaction_param.degree;
//         let input = get_test_circuit(
//             transaction_index,
//             transaction_rlp,
//             merkle_proof,
//             Network::Ethereum(EthereumNetwork::Mainnet),
//         );
//         let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);
//         let params = gen_srs(k);
//         let pk = gen_pk(&params, &circuit, None);
//         let break_points = circuit.circuit.break_points.take();
//         let storage_proof_time = start_timer!(|| "Storage Proof SHPLONK");
//         let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
//         let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
//         end_timer!(storage_proof_time);
//         (snark, storage_proof_time)
//     };
//
//     let k = evm_param.degree;
//     let params = gen_srs(k);
//     set_var("LOOKUP_BITS", evm_param.lookup_bits.to_string());
//     let evm_circuit = AggregationCircuit::public::<SHPLONK>(
//         CircuitBuilderStage::Keygen,
//         None,
//         evm_param.lookup_bits,
//         &params,
//         vec![storage_snark.clone()],
//         false,
//     );
//     evm_circuit.config(k, Some(10));
//     let pk = gen_pk(&params, &evm_circuit, None);
//     let break_points = evm_circuit.break_points();
//
//     let instances = evm_circuit.instances();
//     let evm_proof_time = start_timer!(|| "EVM Proof SHPLONK");
//     let pf_circuit = AggregationCircuit::public::<SHPLONK>(
//         CircuitBuilderStage::Prover,
//         Some(break_points),
//         evm_param.lookup_bits,
//         &params,
//         vec![storage_snark],
//         false,
//     );
//
//     let mut evm = EVM::default();
//     let sols_dir = "../axiom-v1-contracts/contracts/Verify";
//     if PathBuf::new().join(sols_dir).exists() {
//         fs::remove_dir_all(sols_dir).unwrap();
//     }
//     let sols_dir = &PathBuf::new().join(sols_dir);
//     println!("num_instance len :{:?}", evm_circuit.clone().num_instance().len());
//     let generator = halo2_solidity_verifier::SolidityGenerator::new(
//         &params,
//         &pk.get_vk(),
//         Bdfg21,
//         evm_circuit.clone().num_instance().len(),
//     );
//     let sols_gen = generator.render().unwrap();
//     let (verifier_sol, vk_sol) = sols_gen.render_separately().unwrap();
//
//     fs::write(sols_dir.join("Halo2Verifier.sol"), verifier_sol).unwrap();
//     fs::write(sols_dir.join("VerifyingKey.sol"), vk_sol).unwrap();
//     let interface_sol = include_str!("../../gen/IHalo2Verifier.sol");
//     fs::write(sols_dir.join("IHalo2Verifier.sol"), interface_sol).unwrap();
//     let enter_verifier_sol = include_str!("../../gen/Verifier.sol");
//     fs::write(sols_dir.join("Verifier.sol"), enter_verifier_sol).unwrap();
//
//     let proof = gen_evm_proof_shplonk(&params, &pk, pf_circuit, instances.clone());
//     end_timer!(evm_proof_time);
//
//     fs::create_dir_all("data/transaction").unwrap();
//     let vk_creation_code = halo2_solidity_verifier::compile_solidity(&vk_sol);
//     let vk_address = evm.create(vk_creation_code);
//     let call_data =
//         halo2_solidity_verifier::encode_calldata(Some(vk_address.into()), &proof, &instances);
//     // write calldata
//     let call_data_path = Path::new("data/transaction/new.calldata");
//     let call_data = hex::encode(&call_data);
//     fs::write(call_data_path, &call_data)?;
//
//     // let deployment_code = custom_gen_evm_verifier_shplonk(
//     //     &params,
//     //     pk.get_vk(),
//     //     &evm_circuit,
//     //     Some(Path::new("data/transaction/test.yul")),
//     // );
//
//     // this verifies proof in EVM and outputs gas cost (if successful)
//     // evm_verify(deployment_code, instances, proof);
//     //
//     // let keccak_advice = var("KECCAK_ADVICE_COLUMNS")
//     //     .unwrap_or_else(|_| "0".to_string())
//     //     .parse::<usize>()
//     //     .unwrap();
//     // let transaction_params: EthConfigParams =
//     //     serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap();
//     // writeln!(
//     //     fs_results,
//     //     "{},{},{},{:?},{:?},{},{:.2}s,{:?}",
//     //     transaction_params.degree,
//     //     transaction_params.num_rlc_columns
//     //         + transaction_params.num_range_advice.iter().sum::<usize>()
//     //         + transaction_params.num_lookup_advice.iter().sum::<usize>()
//     //         + keccak_advice,
//     //     transaction_params.num_rlc_columns,
//     //     transaction_params.num_range_advice,
//     //     transaction_params.num_lookup_advice,
//     //     transaction_params.num_fixed,
//     //     storage_proof_time.time.elapsed().as_secs_f64(),
//     //     evm_proof_time.time.elapsed()
//     // )
//     //     .unwrap();
//     Ok(())
// }

pub fn encode_instance<F>(instances: &[Vec<F>], path: &Path)
where
    F: PrimeField<Repr = [u8; 32]>,
{
    let instance: Vec<u8> = iter::empty()
        .chain(
            instances
                .iter()
                .flatten()
                .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect_vec()),
        )
        .collect();
    let instance = hex::encode(instance);
    fs::write(path, &instance).unwrap();
}

pub fn encode_proof(proof: &[u8], path: &Path) {
    let proof: Vec<u8> = iter::empty().chain(proof.iter().cloned()).collect();
    let proof = hex::encode(proof);
    fs::write(path, &proof).unwrap();
}
