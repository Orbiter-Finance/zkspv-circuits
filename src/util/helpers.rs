use std::env;

use dotenv::dotenv;
use ethers_core::types::{Address, H256};
use ethers_core::utils::keccak256;
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use zkevm_keccak::util::eth_types::Field;

use crate::{ArbitrumNetwork, EthereumNetwork, Network, OptimismNetwork, ZkSyncEraNetwork};
use crate::block_header::arbitrum::{ARBITRUM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, ARBITRUM_GOERLI_HEADER_FIELDS_MAX_BYTES, ARBITRUM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, ARBITRUM_MAINNET_HEADER_FIELDS_MAX_BYTES};
use crate::block_header::ethereum::{GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, GOERLI_HEADER_FIELDS_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_HEADER_FIELDS_MAX_BYTES};
use crate::block_header::optimism::{OPTIMISM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, OPTIMISM_GOERLI_HEADER_FIELDS_MAX_BYTES, OPTIMISM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, OPTIMISM_MAINNET_HEADER_FIELDS_MAX_BYTES};
use crate::constant::{EIP_1559_TX_TYPE, EIP_2930_TX_TYPE};
use crate::keccak::get_bytes;
use crate::mpt::AssignedBytes;

pub fn get_provider(network: &Network) -> Provider<Http> {
    dotenv().ok();
    let provider_url = match network {
        Network::Ethereum(ethereum_network) => {
            match ethereum_network {
                EthereumNetwork::Mainnet => env::var("MAINNET_RPC").unwrap(),
                EthereumNetwork::Goerli => env::var("GOERLI_RPC").unwrap(),
            }
        }
        Network::Arbitrum(arbitrum_network) => {
            match arbitrum_network {
                ArbitrumNetwork::Mainnet => env::var("ARBITRUM_MAINNET_RPC").unwrap(),
                ArbitrumNetwork::Goerli => env::var("ARBITRUM_GOERLI_RPC").unwrap(),
            }
        }
        Network::Optimism(optimism_network) => {
            match optimism_network {
                OptimismNetwork::Mainnet => env::var("OPTIMISM_MAINNET_RPC").unwrap(),
                OptimismNetwork::Goerli => env::var("OPTIMISM_GOERLI_RPC").unwrap(),
            }
        }
        Network::ZkSync(zksync_network) => {
            match zksync_network {
                ZkSyncEraNetwork::Mainnet => env::var("ZKSYNC_MAINNET_RPC").unwrap(),
                ZkSyncEraNetwork::Goerli => env::var("ZKSYNC_GOERLI_RPC").unwrap(),
            }
        }
    };
    let provider = Provider::<Http>::try_from(provider_url.as_str())
        .expect("could not instantiate HTTP Provider");
    provider
}

pub fn get_network_type(network: &Network) -> usize {
    let network_type = match network {
        Network::Ethereum(ethereum_network) => {
            match ethereum_network {
                EthereumNetwork::Mainnet => 0,
                EthereumNetwork::Goerli => 0,
            }
        }
        Network::Arbitrum(arbitrum_network) => {
            match arbitrum_network {
                ArbitrumNetwork::Mainnet => 1,
                ArbitrumNetwork::Goerli => 1,
            }
        }
        Network::Optimism(optimism_network) => {
            match optimism_network {
                OptimismNetwork::Mainnet => 2,
                OptimismNetwork::Goerli => 2,
            }
        }
        Network::ZkSync(zksync_network) => {
            match zksync_network {
                ZkSyncEraNetwork::Mainnet => 3,
                ZkSyncEraNetwork::Goerli => 3,
            }
        }
    };

    network_type
}


pub fn get_block_header_rlp_max_bytes(network: &Network) -> usize {
    let max_len = match network {
        Network::Ethereum(network) => {
            match network {
                EthereumNetwork::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
                EthereumNetwork::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            }
        }
        Network::Arbitrum(network) => {
            match network {
                ArbitrumNetwork::Mainnet => ARBITRUM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
                ArbitrumNetwork::Goerli => ARBITRUM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            }
        }
        Network::Optimism(network) => {
            match network {
                OptimismNetwork::Mainnet => OPTIMISM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
                OptimismNetwork::Goerli => OPTIMISM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            }
        }

        _ => { 0 }
    };

    max_len
}

pub fn get_mainnet_block_header_rlp_max_field_lens(network: &Network) -> [usize; 17] {
    let mut max_field_lens = [0; 17];
    if let Network::Ethereum(ethereum_network) = network {
        max_field_lens = match ethereum_network {
            EthereumNetwork::Mainnet => MAINNET_HEADER_FIELDS_MAX_BYTES,
            EthereumNetwork::Goerli => GOERLI_HEADER_FIELDS_MAX_BYTES,
        }
    }

    max_field_lens
}

pub fn get_arbitrum_block_header_rlp_max_field_lens(network: &Network) -> [usize; 16] {
    let mut max_field_lens = [0; 16];
    if let Network::Arbitrum(arbitrum_network) = network {
        max_field_lens = match arbitrum_network {
            ArbitrumNetwork::Mainnet => ARBITRUM_MAINNET_HEADER_FIELDS_MAX_BYTES,
            ArbitrumNetwork::Goerli => ARBITRUM_GOERLI_HEADER_FIELDS_MAX_BYTES,
        }
    }

    max_field_lens
}

pub fn get_optimism_block_header_rlp_max_field_lens(network: &Network) -> [usize; 17] {
    let mut max_field_lens = [0; 17];
    if let Network::Optimism(optimism_network) = network {
        max_field_lens = match optimism_network {
            OptimismNetwork::Mainnet => OPTIMISM_MAINNET_HEADER_FIELDS_MAX_BYTES,
            OptimismNetwork::Goerli => OPTIMISM_GOERLI_HEADER_FIELDS_MAX_BYTES,
        }
    }

    max_field_lens
}

pub fn get_transaction_type<F: Field>(ctx: &mut Context<F>, value: &AssignedValue<F>) -> usize {
    let eip_1559_prefix = (F::from(EIP_1559_TX_TYPE as u64)).try_into().unwrap();
    let eip_1559_prefix = ctx.load_witness(eip_1559_prefix);
    let eip_2930_prefix = (F::from(EIP_2930_TX_TYPE as u64)).try_into().unwrap();
    let eip_2930_prefix = ctx.load_witness(eip_2930_prefix);
    let transaction_type =
        if value.value == eip_1559_prefix.value {
            2
        } else if value.value == eip_2930_prefix.value {
            1
        } else { 0 };

    transaction_type
}

pub fn bytes_to_vec_u8<F: Field>(bytes_value: &AssignedBytes<F>) -> Vec<u8> {
    let input_bytes: Option<Vec<u8>> = None;
    bytes_to_vec_u8_impl(bytes_value, input_bytes)
}

/// 1:a>b  -1:a<b   0:a==b
pub fn bytes_to_vec_u8_gt_or_lt<F: Field>(bytes_value_one: &AssignedBytes<F>, bytes_value_two: &AssignedBytes<F>) -> isize {
    let input_bytes: Option<Vec<u8>> = None;
    let bytes_value_one = bytes_to_vec_u8_impl(bytes_value_one, input_bytes.clone());
    let bytes_value_two = bytes_to_vec_u8_impl(bytes_value_two, input_bytes);
    return if bytes_value_one.gt(&bytes_value_two) {
        1
    } else if bytes_value_one.lt(&bytes_value_two) {
        -1
    } else { 0 };
}

fn bytes_to_vec_u8_impl<F: Field>(bytes_value: &AssignedBytes<F>, input_bytes: Option<Vec<u8>>) -> Vec<u8> {
    input_bytes.unwrap_or_else(|| get_bytes(&bytes_value[..]))
}

pub fn bytes_to_u8<F: Field>(bytes_value: &AssignedValue<F>) -> u8 {
    let input_bytes: Option<u8> = None;
    bytes_to_u8_impl(bytes_value, input_bytes)
}

fn bytes_to_u8_impl<F: Field>(bytes_value: &AssignedValue<F>, input_bytes: Option<u8>) -> u8 {
    input_bytes.unwrap_or_else(|| bytes_value.value().get_lower_32() as u8)
}


pub fn load_bytes<F: Field>(ctx: &mut Context<F>, bytes: &[u8]) -> Vec<AssignedValue<F>> {
    ctx.assign_witnesses(bytes.iter().map(|x| F::from(*x as u64)))
}

/// keccak(LeftPad32(key, 0), LeftPad32(map position, 0))
pub fn calculate_storage_mapping_key(mapping_layout: H256, address: Address) -> H256 {
    let internal_bytes = [H256::from(address).to_fixed_bytes(), mapping_layout.to_fixed_bytes()].concat();
    H256::from(keccak256(internal_bytes))
}

