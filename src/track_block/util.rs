use crate::track_block::EthTrackBlockCircuit;
use crate::util::helpers::get_provider;
use crate::Network;

#[derive(Clone, Debug)]
pub struct TrackBlockConstructor {
    pub block_number_interval: Vec<u64>,
    pub network: Network,
}

pub fn get_eth_track_block_circuit(constructor: TrackBlockConstructor) -> EthTrackBlockCircuit {
    let provider = get_provider(&constructor.network);

    EthTrackBlockCircuit::from_provider(&provider, constructor)
}
