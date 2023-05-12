use std::env;

use dotenv::dotenv;
use ethers_providers::{Http, Provider};

use crate::{ArbitrumNetwork, EthereumNetwork, Network};
use crate::block_header::{GOERLI_BLOCK_HEADER_RLP_MAX_BYTES, GOERLI_HEADER_FIELDS_MAX_BYTES, MAINNET_BLOCK_HEADER_RLP_MAX_BYTES, MAINNET_HEADER_FIELDS_MAX_BYTES};
use crate::providers::{ARBITRUM_GOERLI_PROVIDER_URL, GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL};

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

pub fn get_block_header_type(network:&Network)-> usize{
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
                ArbitrumNetwork::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
                ArbitrumNetwork::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
            }
        }
    };

    max_len
}

pub fn get_block_header_rlp_max_field_lens(network:&Network) -> [usize; 17] {
    let max_field_lens = match network {
        Network::Ethereum(ethereum_network) => {
            match ethereum_network {
                EthereumNetwork::Mainnet => MAINNET_HEADER_FIELDS_MAX_BYTES,
                EthereumNetwork::Goerli => GOERLI_HEADER_FIELDS_MAX_BYTES,
            }
        }
        Network::Arbitrum(arbitrum_network) => {
            match arbitrum_network {
                ArbitrumNetwork::Mainnet => MAINNET_HEADER_FIELDS_MAX_BYTES,
                ArbitrumNetwork::Goerli => GOERLI_HEADER_FIELDS_MAX_BYTES,
            }
        }
    };

    max_field_lens
}