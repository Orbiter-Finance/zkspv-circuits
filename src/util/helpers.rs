use std::env;

use dotenv::dotenv;
use ethers_providers::{Http, Provider};
use halo2_base::{AssignedValue, Context};
use zkevm_keccak::util::eth_types::Field;

use crate::{ArbitrumNetwork, EthereumNetwork, Network};
use crate::arbitrum_block_header::{ARBITRUM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, ARBITRUM_GOERLI_HEADER_FIELDS_MAX_BYTES, ARBITRUM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, ARBITRUM_MAINNET_HEADER_FIELDS_MAX_BYTES};
use crate::block_header::{GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, GOERLI_HEADER_FIELDS_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_HEADER_FIELDS_MAX_BYTES};
use crate::keccak::get_bytes;
use crate::mpt::AssignedBytes;
use crate::providers::{ARBITRUM_GOERLI_PROVIDER_URL, GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL};
use crate::r#type::{EIP_1559_TX_TYPE, EIP_2930_TX_TYPE};

pub fn get_provider(network: &Network) -> Provider<Http> {
    dotenv().ok();
    let alchemy_id = env::var("ALCHEMY_ID").unwrap();
    let provider_url = match network {
        Network::Ethereum(ethereum_network) => {
            match ethereum_network {
                EthereumNetwork::Mainnet => format!("{MAINNET_PROVIDER_URL}{alchemy_id}"),
                EthereumNetwork::Goerli => format!("{GOERLI_PROVIDER_URL}{alchemy_id}"),
            }
        }
        Network::Arbitrum(arbitrum_network) => {
            match arbitrum_network {
                ArbitrumNetwork::Mainnet => format!("{ARBITRUM_GOERLI_PROVIDER_URL}{alchemy_id}"),
                ArbitrumNetwork::Goerli => format!("{ARBITRUM_GOERLI_PROVIDER_URL}{alchemy_id}"),
            }
        }
    };
    let provider = Provider::<Http>::try_from(provider_url.as_str())
        .expect("could not instantiate HTTP Provider");
    provider
}

pub fn get_block_header_type(network: &Network) -> usize {
    let header_type = match network {
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
    };

    header_type
}


pub fn get_block_header_rlp_max_bytes(network: &Network) -> usize {
    let max_len = match network {
        Network::Ethereum(ethereum_network) => {
            match ethereum_network {
                EthereumNetwork::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
                EthereumNetwork::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            }
        }
        Network::Arbitrum(arbitrum_network) => {
            match arbitrum_network {
                ArbitrumNetwork::Mainnet => ARBITRUM_MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
                ArbitrumNetwork::Goerli => ARBITRUM_GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            }
        }
    };

    max_len
}

pub fn get_block_header_rlp_max_field_lens(network: &Network) -> [usize; 17] {
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

pub fn bytes_to_vec_u8<F: Field>(bytes_value: &AssignedBytes<F>, input_bytes: Option<Vec<u8>>) -> Vec<u8> {
    input_bytes.unwrap_or_else(|| get_bytes(&bytes_value[..]))
}