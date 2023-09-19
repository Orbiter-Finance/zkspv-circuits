use crate::{ Network };
use crate::track_block::EthTrackBlockCircuit;

use crate::util::helpers::get_provider;

pub fn get_eth_track_block_circuit(
    block_number_interval: Vec<u64>,
    network: Network,
) -> EthTrackBlockCircuit {
    let provider = get_provider(&network);
    EthTrackBlockCircuit::from_provider(&provider, block_number_interval, network)
}