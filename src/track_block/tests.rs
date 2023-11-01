use crate::halo2_proofs::dev::MockProver;
use crate::rlp::builder::RlcThreadBuilder;
use crate::track_block::util::TrackBlockConstructor;
use crate::track_block::EthTrackBlockCircuit;
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{EthPreCircuit, EthereumNetwork, Network};
use std::env::set_var;

fn get_test_circuit(blocks_number: Vec<u64>, network: Network) -> EthTrackBlockCircuit {
    let provider = get_provider(&network);
    let constructor = TrackBlockConstructor { blocks_number, network };
    EthTrackBlockCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_track_block() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/track_block.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let blocks_number = vec![17113952, 17113957, 17113959];

    let input = get_test_circuit(blocks_number, Network::Ethereum(EthereumNetwork::Mainnet));
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}
