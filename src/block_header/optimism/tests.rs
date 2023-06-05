use crate::{keccak::SharedKeccakChip, Network, OptimismNetwork, util::{EthConfigPinning, Halo2ConfigPinning}};

use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    utils::fs::gen_srs,
};
use hex::FromHex;
use rand_core::OsRng;
use std::{env::set_var, fs::File, marker::PhantomData};
use test_log::test;
use zkevm_keccak::util::eth_types::Field;
use crate::util::EthConfigParams;

fn block_header_test_circuit<F: Field>(
    mut builder: RlcThreadBuilder<F>,
    inputs: Vec<Vec<u8>>,
    network: Network,
    break_points: Option<RlcThreadBreakPoints>,
) -> EthCircuitBuilder<F, impl FnSynthesize<F>> {
    let prover = builder.witness_gen_only();
    let range = RangeChip::default(ETH_LOOKUP_BITS);
    let keccak = SharedKeccakChip::default();
    let chip = EthChip::new(RlpChip::new(&range, None), None);
    let chain_witness = chip.decompose_block_header_chain_phase0(
        &mut builder.gate_builder,
        &mut keccak.borrow_mut(),
        &inputs,
        network,
    );

    let circuit = EthCircuitBuilder::new(
        vec![],
        builder,
        keccak,
        range,
        break_points,
        move |builder: &mut RlcThreadBuilder<F>,
              rlp: RlpChip<F>,
              keccak_rlcs: (FixedLenRLCs<F>, VarLenRLCs<F>)| {
            let chip = EthChip::new(rlp, Some(keccak_rlcs));
            let _block_chain_trace =
                chip.decompose_block_header_chain_phase1(builder, chain_witness, None);
        },
    );
    if !prover {
        let config_params: EthConfigParams = serde_json::from_str(
            var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
        )
            .unwrap();
        circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
    }
    circuit
}

#[test]
pub fn test_one_optimism_mainnet_header_mock() {
    let params = EthConfigPinning::from_path("configs/tests/one_block.json").params;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input_hex = "f9025ca0b3743f7704657c562e09bd8c3805e637bf44ee222d6e9220e6288d4cc06faebda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a02ccb2c12dffe13d6d6c552ca045f924d9ac2fbaeeb7a0fe9a0e28f119b91720ca03b5d9ce89ce6cedad8825d9c729ee905eb8627a6b3a8c52155284f5f38af3a24a0056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002840621687e83e4e1c0825208846475bc8cb861d98301090a846765746889676f312e31352e3133856c696e757800000000000083894112bfba4c20f291da36fefbb8c34f54174db8ef023197eaffae1171d80e219b63e182c832e18b98b699ac50919aaa44c02844311fb5a02386f8c5eeabeb00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(OPTIMISM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let circuit = block_header_test_circuit::<Fr>(
        RlcThreadBuilder::mock(),
        vec![input_bytes],
        Network::Optimism(OptimismNetwork::Mainnet),
        None,
    );
    MockProver::run(k, &circuit, vec![vec![]]).unwrap().assert_satisfied();
}
#[test]
pub fn test_one_optimism_goerli_header_mock() {
    let params = EthConfigPinning::from_path("configs/tests/one_block.json").params;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input_hex = "f901fba0d132f078d998e350708a04dc5c3dc9f664aaf15d6fb385d0197a427093bbee85a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a040e5965f4cca73486217a7768d31f4c704be3e972a74983dce6b8a19b8b977f9a08922caa9fefb1c65999d76757c57a2877ccd4a162d73cde303df15a6c2fb410aa00576558a5adb0de6368acaab7fa479e1976d23899e16eeb8095ad85451d87405b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008083987c6a8402faf08082c515846475633880a0d5b89f6add71c1c7dac89dd9a38085f99ad3639f3efcbc5664c0762fd357120788000000000000000032";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(OPTIMISM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let circuit = block_header_test_circuit::<Fr>(
        RlcThreadBuilder::mock(),
        vec![input_bytes],
        Network::Optimism(OptimismNetwork::Goerli),
        None,
    );
    MockProver::run(k, &circuit, vec![vec![]]).unwrap().assert_satisfied();
}


#[test]
pub fn test_one_mainnet_header_prover() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigPinning::from_path("configs/tests/one_block.json").params;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input_hex = "f90222a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e6a0f7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549";
    let mut input_bytes: Vec<u8> = Vec::from_hex(input_hex).unwrap();
    input_bytes.resize(OPTIMISM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, 0);

    let mut rng = OsRng;
    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let circuit = block_header_test_circuit::<Fr>(
        RlcThreadBuilder::keygen(),
        vec![input_bytes.clone()],
        Network::Ethereum(EthereumNetwork::Mainnet),
        None,
    );
    let vk_time = start_timer!(|| "vk gen");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pk gen");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);
    let break_points = circuit.circuit.break_points.take();
    let pinning = EthConfigPinning {
        params: serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap(),
        break_points,
    };
    serde_json::to_writer(File::create("configs/tests/one_block.json").unwrap(), &pinning)?;

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let pf_time = start_timer!(|| "proof gen");
    let break_points = pinning.break_points();
    let circuit = block_header_test_circuit::<Fr>(
        RlcThreadBuilder::prover(),
        vec![input_bytes],
        Network::Ethereum(EthereumNetwork::Mainnet),
        Some(break_points),
    );
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[&[]]], rng, &mut transcript)?;
    let proof = transcript.finalize();
    end_timer!(pf_time);

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_time = start_timer!(|| "verify");
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[&[]]], &mut transcript)
        .unwrap();
    end_timer!(verify_time);

    Ok(())
}

fn get_default_goerli_header_chain_circuit() -> EthBlockHeaderChainCircuit<Fr> {
    let network = Network::Ethereum(EthereumNetwork::Goerli);
    let header_rlp_max_bytes = OPTIMISM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES;
    let blocks: Vec<String> =
        serde_json::from_reader(File::open("data/headers/default_blocks_goerli.json").unwrap())
            .unwrap();
    let mut input_bytes = Vec::new();
    let max_depth = 3;
    for block_str in blocks.iter() {
        let mut block_vec: Vec<u8> = Vec::from_hex(block_str).unwrap();
        block_vec.resize(header_rlp_max_bytes, 0);
        input_bytes.push(block_vec);
    }
    let dummy_header_rlp = input_bytes[0].clone();
    input_bytes.extend(iter::repeat(dummy_header_rlp).take((1 << max_depth) - input_bytes.len()));

    EthBlockHeaderChainCircuit {
        header_rlp_encodings: input_bytes,
        num_blocks: 7,
        max_depth,
        network,
        _marker: PhantomData,
    }
}

#[test]
pub fn test_multi_goerli_header_mock() {
    let config = EthConfigPinning::from_path("configs/tests/multi_block.json").params;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&config).unwrap());
    let k = config.degree;

    let input = get_default_goerli_header_chain_circuit();
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    let instance = circuit.instance();

    MockProver::run(k, &circuit, vec![instance]).unwrap().assert_satisfied();
}

#[test]
pub fn test_multi_goerli_header_prover() {
    let config = EthConfigPinning::from_path("configs/tests/multi_block.json").params;
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&config).unwrap());
    let k = config.degree;
    let input = get_default_goerli_header_chain_circuit();
    let circuit = input.clone().create_circuit(RlcThreadBuilder::keygen(), None);

    let params = gen_srs(k);

    let vk_time = start_timer!(|| "vk gen");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pk gen");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);
    let break_points = circuit.circuit.break_points.take();
    let pinning = EthConfigPinning {
        params: serde_json::from_str(var("ETH_CONFIG_PARAMS").unwrap().as_str()).unwrap(),
        break_points,
    };
    serde_json::to_writer(File::create("configs/tests/multi_block.json").unwrap(), &pinning)
        .unwrap();

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let pf_time = start_timer!(|| "proof gen");
    let break_points = pinning.break_points();
    let circuit = input.create_circuit(RlcThreadBuilder::prover(), Some(break_points));
    let instance = circuit.instance();
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[&instance]], OsRng, &mut transcript)
        .unwrap();
    let proof = transcript.finalize();
    end_timer!(pf_time);

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_time = start_timer!(|| "verify");
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[&instance]], &mut transcript)
        .unwrap();
    end_timer!(verify_time);
}

#[cfg(all(feature = "aggregation", feature = "providers"))]
mod aggregation {
    use std::path::PathBuf;

    use crate::util::scheduler::Scheduler;
    use crate::block_header::optimism::helpers::{BlockHeaderScheduler, CircuitType, Finality, Task};

    use super::*;
    use super::test;

    fn test_scheduler(network: Network) -> BlockHeaderScheduler {
        BlockHeaderScheduler::new(
            network,
            false,
            false,
            PathBuf::from("configs/headers"),
            PathBuf::from("data/headers"),
        )
    }

    #[test]
    fn test_goerli_header_chain_provider() {
        let scheduler = test_scheduler(Network::Ethereum(EthereumNetwork::Goerli));
        scheduler.get_snark(Task::new(
            0x765fb3,
            0x765fb3 + 7,
            CircuitType::new(3, 3, Finality::None, Network::Ethereum(EthereumNetwork::Goerli)),
        ));
    }

    #[test]
    #[ignore = "requires over 32G memory"]
    fn test_goerli_header_chain_with_aggregation() {
        let scheduler = test_scheduler(Network::Ethereum(EthereumNetwork::Goerli));
        scheduler.get_snark(Task::new(
            0x765fb3,
            0x765fb3 + 11,
            CircuitType::new(4, 3, Finality::None, Network::Ethereum(EthereumNetwork::Goerli)),
        ));
    }

    #[test]
    #[ignore = "requires over 32G memory"]
    fn test_goerli_header_chain_final_aggregation() {
        let scheduler = test_scheduler(Network::Ethereum(EthereumNetwork::Goerli));
        scheduler.get_snark(Task::new(
            0x765fb3,
            0x765fb3 + 9,
            CircuitType::new(4, 3, Finality::Merkle, Network::Ethereum(EthereumNetwork::Goerli)),
        ));
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_goerli_header_chain_for_evm() {
        let scheduler = test_scheduler(Network::Ethereum(EthereumNetwork::Goerli));
        scheduler.get_calldata(
            Task::new(
                0x765fb3,
                0x765fb3 + 11,
                CircuitType::new(4, 3, Finality::Evm(1), Network::Ethereum(EthereumNetwork::Goerli)),
            ),
            true,
        );
    }
}
