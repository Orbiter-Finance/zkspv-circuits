use std::env::set_var;
use crate::{EthereumNetwork, Network};
use crate::rlp::builder::RlcThreadBuilder;
use crate::track_block::EthTrackBlockCircuit;
use crate::util::EthConfigParams;
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Fr},
};
use crate::util::helpers::get_provider;

fn get_test_circuit(
    block_number_interval: Vec<u64>,
    network: Network,
) -> EthTrackBlockCircuit {
    let provider = get_provider(&network);
    EthTrackBlockCircuit::from_provider(&provider, block_number_interval, network)
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

    let input = get_test_circuit(block_number_interval, Network::Ethereum(EthereumNetwork::Mainnet));
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);
    println!("instance:{:?}", circuit.instance());
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}