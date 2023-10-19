use crate::halo2_proofs::dev::MockProver;
use crate::rlp::builder::RlcThreadBuilder;
use crate::track_block::util::TrackBlockConstructor;
use crate::track_block::EthTrackBlockCircuit;
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{EthPreCircuit, EthereumNetwork, Network};
use std::env::set_var;
use std::ops::Range;

fn get_test_circuit(
    block_number_interval: Vec<u64>,
    block_target: u64,
    network: Network,
) -> EthTrackBlockCircuit {
    let provider = get_provider(&network);
    let constructor = TrackBlockConstructor { block_number_interval, block_target, network };
    EthTrackBlockCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_track_block() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/track_block.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let mut block_number_interval = vec![];
    for i in 17113952..17113973 {
        block_number_interval.push(i as u64);
    }

    let block_target = 17113953;

    let input = get_test_circuit(
        block_number_interval,
        block_target,
        Network::Ethereum(EthereumNetwork::Mainnet),
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}
