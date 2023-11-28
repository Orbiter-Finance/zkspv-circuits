use crate::arbitration::helper::FinalAssemblyConstructor;
use crate::arbitration::network_pairs::from_ethereum_to_zksync::parse_from_ethereum_to_zksync;
use crate::arbitration::network_pairs::from_zksync_to_ethereum::parse_from_zksync_to_ethereum;
use crate::arbitration::types::{BatchBlocksInput, ObContractStorageInput, TransactionInput};
use crate::util::errors::{ErrorType, COMMIT_TRANSACTION_IS_EMPTY};
use crate::Network;
use serde::{Deserialize, Serialize};

mod from_ethereum_to_zksync;
mod from_zksync_to_ethereum;
mod utils;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkPairs {
    FromEthereumToZkSync(Network, Network, bool),
    FromZkSyncToEthereum(Network, Network, bool),
}

impl NetworkPairs {
    pub fn new_pairs(from_network: Network, to_network: Network, is_source: bool) -> Option<Self> {
        if matches!(from_network, Network::Ethereum(_)) && matches!(to_network, Network::ZkSync(_))
        {
            return Some(NetworkPairs::FromEthereumToZkSync(from_network, to_network, is_source));
        } else if matches!(from_network, Network::ZkSync(_))
            && matches!(to_network, Network::Ethereum(_))
        {
            return Some(NetworkPairs::FromZkSyncToEthereum(from_network, to_network, is_source));
        }
        None
    }

    pub fn parse_pairs_task(
        &self,
        ob_contract_storage_input: Option<ObContractStorageInput>,
        batch_blocks_input: Option<BatchBlocksInput>,
        original_transaction: TransactionInput,
        commit_transaction: Option<TransactionInput>,
    ) -> FinalAssemblyConstructor {
        match self {
            NetworkPairs::FromEthereumToZkSync(_, ..) => parse_from_ethereum_to_zksync(
                self,
                ob_contract_storage_input,
                batch_blocks_input,
                original_transaction,
                commit_transaction,
            ),
            NetworkPairs::FromZkSyncToEthereum(_, ..) => parse_from_zksync_to_ethereum(
                self,
                ob_contract_storage_input,
                batch_blocks_input,
                original_transaction,
                commit_transaction,
            ),
        }
    }

    pub fn get_details(&self) -> (Network, Network, bool) {
        match self {
            NetworkPairs::FromEthereumToZkSync(from_network, to_network, is_source) => {
                (from_network.clone(), to_network.clone(), *is_source)
            }
            NetworkPairs::FromZkSyncToEthereum(from_network, to_network, is_source) => {
                (from_network.clone(), to_network.clone(), *is_source)
            }
        }
    }

    /// return l1_network,l2_network
    pub fn get_layer_network(&self) -> (Network, Network) {
        let (from_network, to_network, _) = self.get_details();
        if from_network.is_l1() {
            (from_network, to_network)
        } else {
            (to_network, from_network)
        }
    }
}
