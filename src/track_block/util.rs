use super::{BlockMerkleInclusionCircuit, BlockMerkleInclusionConstructor};
use crate::track_block::EthTrackBlockCircuit;
use crate::util::helpers::get_provider;
use crate::Network;

#[derive(Clone, Debug)]
pub struct TrackBlockConstructor {
    pub blocks_number: Vec<u64>,
    pub network: Network,
}

pub fn get_eth_track_block_circuit(constructor: TrackBlockConstructor) -> EthTrackBlockCircuit {
    let provider = get_provider(&constructor.network);

    EthTrackBlockCircuit::from_provider(&provider, constructor)
}

pub fn get_merkle_inclusion_circuit(
    from_provider: bool,
    network: Option<Network>,
    constructors: Option<Vec<BlockMerkleInclusionConstructor>>,
) -> BlockMerkleInclusionCircuit {
    // let provider = get_provider(&constructor.network);
    if !from_provider {
        // This can only be used in test case!
        return BlockMerkleInclusionCircuit::from_json();
    } else {
        return BlockMerkleInclusionCircuit::from_provider(
            &network.expect("Network is None"),
            &constructors.expect("Constructors is None"),
        );
    }
}
