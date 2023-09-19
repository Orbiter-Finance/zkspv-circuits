use ethers_core::{types::{Address, H256}, utils::keccak256};

use crate::{Network, EthereumNetwork, config::contract::get_mdc_config, util::helpers::get_provider};

use super::EthBlockStorageCircuit;


pub fn get_mdc_storage_circuit(network: Network, block_number: u32) -> EthBlockStorageCircuit{

    let mut addr = Default::default();
    let num_slots = 1;
    let mdc_config = get_mdc_config();
    let provider = get_provider(&network);

    match network {
        Network::Ethereum(EthereumNetwork::Mainnet) => {
            addr = mdc_config.mainnet;
        }
        Network::Ethereum(EthereumNetwork::Goerli) => {
            addr = mdc_config.goerli;
        }
        _ => { panic!("no match network Type! {:?}", network)}
    }

    // For only occupied slots:
    let slot_nums = vec![0u64, 1u64, 2u64, 3u64, 6u64, 8u64];
    let mut slots = (0..4)
        .map(|x| {
            let mut bytes = [0u8; 64];
            bytes[31] = x;
            bytes[63] = 10;
            H256::from_slice(&keccak256(bytes))
        })
        .collect::<Vec<_>>();
    slots.extend(slot_nums.iter().map(|x| H256::from_low_u64_be(*x)));
    slots.truncate(num_slots);
    // let slots: Vec<_> = (0..num_slots).map(|x| H256::from_low_u64_be(x as u64)).collect();
    slots.truncate(num_slots);
    EthBlockStorageCircuit::from_provider(&provider, block_number, addr, slots, 8, 8, network)

}