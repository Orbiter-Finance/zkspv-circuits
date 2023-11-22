use ethers_core::abi;
use ethers_core::abi::{AbiEncode, Token, Uint};
use ethers_core::types::{Address, BigEndianHash, H256};
use ethers_core::utils::keccak256;
use ethers_providers::{Http, Middleware, Provider};
use halo2_base::{AssignedValue, Context};
use std::ops::Add;
use tokio::runtime::Runtime;
use zkevm_keccak::util::eth_types::Field;

use crate::config::rpcs::get_rpcs_config;
use crate::keccak::get_bytes;
use crate::mpt::AssignedBytes;
use crate::{ArbitrumNetwork, EthereumNetwork, Network, OptimismNetwork, ZkSyncEraNetwork};

pub fn get_block_batch_hashes(
    provider: &Provider<Http>,
    start_block_num: u32,
    end_block_num: u32,
) -> Vec<H256> {
    let rt = Runtime::new().unwrap();
    assert!(start_block_num <= end_block_num);
    let mut leaves = Vec::with_capacity((end_block_num - start_block_num) as usize);
    for block_num in start_block_num..=end_block_num {
        let block = rt.block_on(provider.get_block(block_num as u64)).unwrap().unwrap();
        let block_hash = block.hash.unwrap();
        println!("block_num:{:?},block_hash:{:?}", block_num, block_hash);
        leaves.push(block_hash);
    }
    leaves
}

pub fn get_provider(network: &Network) -> Provider<Http> {
    let rpcs = get_rpcs_config();
    let provider_url = match network {
        Network::Ethereum(ethereum_network) => match ethereum_network {
            EthereumNetwork::Mainnet => rpcs.ethereum.mainnet,
            EthereumNetwork::Goerli => rpcs.ethereum.goerli,
        },
        Network::Arbitrum(arbitrum_network) => match arbitrum_network {
            ArbitrumNetwork::Mainnet => rpcs.arbitrum.mainnet,
            ArbitrumNetwork::Goerli => rpcs.arbitrum.goerli,
        },
        Network::Optimism(optimism_network) => match optimism_network {
            OptimismNetwork::Mainnet => rpcs.optimism.mainnet,
            OptimismNetwork::Goerli => rpcs.optimism.goerli,
        },
        Network::ZkSync(zksync_network) => match zksync_network {
            ZkSyncEraNetwork::Mainnet => rpcs.zksync_era.mainnet,
            ZkSyncEraNetwork::Goerli => rpcs.zksync_era.goerli,
        },
    };
    let provider = Provider::<Http>::try_from(provider_url.as_str())
        .expect("could not instantiate HTTP Provider");
    provider
}

pub fn bytes_to_vec_u8<F: Field>(bytes_value: &AssignedBytes<F>) -> Vec<u8> {
    let input_bytes: Option<Vec<u8>> = None;
    bytes_to_vec_u8_impl(bytes_value, input_bytes)
}

/// 1:a>b  -1:a<b   0:a==b
pub fn bytes_to_vec_u8_gt_or_lt<F: Field>(
    bytes_value_one: &AssignedBytes<F>,
    bytes_value_two: &AssignedBytes<F>,
) -> isize {
    let input_bytes: Option<Vec<u8>> = None;
    let bytes_value_one = bytes_to_vec_u8_impl(bytes_value_one, input_bytes.clone());
    let bytes_value_two = bytes_to_vec_u8_impl(bytes_value_two, input_bytes);
    return if bytes_value_one.gt(&bytes_value_two) {
        1
    } else if bytes_value_one.lt(&bytes_value_two) {
        -1
    } else {
        0
    };
}

fn bytes_to_vec_u8_impl<F: Field>(
    bytes_value: &AssignedBytes<F>,
    input_bytes: Option<Vec<u8>>,
) -> Vec<u8> {
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
    let internal_bytes =
        [H256::from(address).to_fixed_bytes(), mapping_layout.to_fixed_bytes()].concat();
    H256::from(keccak256(internal_bytes))
}

/// used for mapping(address => struct)
///
/// key:address
///
/// mapping_position:Map the storage location in the contract
///
/// slot_position:The position of the structure element to be obtained.
pub fn calculate_mk_address_struct(
    key: Address,
    mapping_position: usize,
    slot_position: usize,
) -> H256 {
    let encoded = abi::encode(&[Token::Address(key), Token::Uint(Uint::from(mapping_position))]);
    let slot = keccak256(encoded);
    let slot = Uint::from(slot).add(slot_position);
    H256::from_uint(&slot)
}
