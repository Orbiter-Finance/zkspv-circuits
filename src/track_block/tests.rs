use std::env::set_var;
use ethers_providers::{Http, Provider};
use crate::Network;
use crate::rlp::builder::RlcThreadBuilder;
use crate::track_block::EthTrackBlockCircuit;
use crate::util::EthConfigParams;
use crate::providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL};
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Fr},
};

fn get_test_circuit(
    block_number_interval: Vec<u64>,
    network: Network,
) -> EthTrackBlockCircuit {
    let infura_id = "870df3c2a62e4b8a81d466ef1b1cbefd";
    let provider_url = match network {
        Network::Mainnet => format!("{MAINNET_PROVIDER_URL}{infura_id}"),
        Network::Goerli => format!("{GOERLI_PROVIDER_URL}{infura_id}"),
    };
    let provider = Provider::<Http>::try_from(provider_url.as_str())
        .expect("could not instantiate HTTP Provider");
    EthTrackBlockCircuit::from_provider(&provider, block_number_interval, Network::Mainnet)
}

#[test]
pub fn test_track_block() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/track_block.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let mut block_number_interval = vec![];
    for i in 17113952..17114152 {
        block_number_interval.push(i as u64);
    }

    let input = get_test_circuit(block_number_interval, Network::Mainnet);
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);
    println!("instance:{:?}", circuit.instance());
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}