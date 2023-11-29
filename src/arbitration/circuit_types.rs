use std::path::Path;

use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::transaction::EthTransactionType;
use crate::util::AggregationConfigPinning;
use crate::{
    util::{scheduler, EthConfigPinning, Halo2ConfigPinning},
    Network,
};
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlockMerkleInclusionCircuitType {
    pub network: Network,
    pub block_batch_num: u64,
    pub tree_depth: u64,
    pub block_range_length: u64,
}

impl BlockMerkleInclusionCircuitType {
    fn name(&self) -> String {
        format!(
            "batch_block_merkle_depth_{}_length_{}_num_{}",
            self.tree_depth, self.block_range_length, self.block_batch_num
        )
    }
}

impl scheduler::CircuitType for BlockMerkleInclusionCircuitType {
    fn name(&self) -> String {
        self.name()
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        EthConfigPinning::from_path(pinning_path.as_ref()).degree()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthTransactionCircuitType {
    pub network: Network,
    pub tx_type: EthTransactionType,
    pub tasks_len: u64,
    pub tx_max_len: u64,
    pub aggregated: bool,
}

impl EthTransactionCircuitType {
    pub fn is_aggregated(&self) -> bool {
        self.aggregated
    }
}

impl scheduler::CircuitType for EthTransactionCircuitType {
    fn name(&self) -> String {
        if self.is_aggregated() {
            format!(
                "transaction_aggregate_{}_tasks_len_{}",
                self.tx_type.to_string(),
                self.tasks_len
            )
        } else {
            format!(
                "{}_transaction_{}_max_len_{}",
                self.network.to_string(),
                self.tx_type.to_string(),
                self.tx_max_len
            )
        }
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.is_aggregated() {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthReceiptCircuitType {
    pub network: Network,
    pub aggregated: bool,
}

impl EthReceiptCircuitType {
    pub fn is_aggregated(&self) -> bool {
        self.aggregated
    }
}

impl scheduler::CircuitType for EthReceiptCircuitType {
    fn name(&self) -> String {
        if self.is_aggregated() {
            format!("receipt_aggregate",)
        } else {
            format!("receipt",)
        }
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.is_aggregated() {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthTransactionReceiptCircuitType {
    pub network: Network,
    pub tx_type: EthTransactionType,
    pub tasks_len: u64,
    pub tx_max_len: u64,
    pub aggregated: bool,
}

impl EthTransactionReceiptCircuitType {
    pub fn is_aggregated(&self) -> bool {
        self.aggregated
    }
}

impl scheduler::CircuitType for EthTransactionReceiptCircuitType {
    fn name(&self) -> String {
        if self.is_aggregated() {
            format!(
                "transaction_receipt_aggregate_{}_tasks_len_{}",
                self.tx_type.to_string(),
                self.tasks_len
            )
        } else {
            format!(
                "{}_transaction_receipt_{}_max_len_{}",
                self.network.to_string(),
                self.tx_type.to_string(),
                self.tx_max_len
            )
        }
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.is_aggregated() {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EthStorageCircuitType {
    pub network: Network,
    pub single_block_include_contracts: u64,
    pub multi_blocks_number: u64,
    pub aggregated: bool,
}

impl EthStorageCircuitType {
    pub(crate) fn name(&self) -> String {
        if self.is_aggregated() {
            format!(
                "storage_aggregate_single_block_include_contracts_{}_multi_blocks_number_{}",
                self.single_block_include_contracts, self.multi_blocks_number
            )
        } else {
            format!(
                "storage_width_single_block_include_contracts_{}_multi_blocks_number_{}",
                self.single_block_include_contracts, self.multi_blocks_number
            )
        }
    }
    pub(crate) fn is_aggregated(&self) -> bool {
        self.aggregated
    }
}

impl scheduler::CircuitType for EthStorageCircuitType {
    fn name(&self) -> String {
        self.name()
    }

    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        if self.is_aggregated() {
            AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
        } else {
            EthConfigPinning::from_path(pinning_path.as_ref()).degree()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FinalAssemblyFinality {
    None,
    Evm(usize),
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FinalAssemblyCircuitType {
    /// Performs `round` rounds of SNARK verification using `PublicAggregationCircuit` on the final circuit.
    /// This is used to reduce circuit size and final EVM verification gas costs.
    pub round: usize,
    pub aggregation_type: FinalAssemblyType,
    pub from_network: Network,
    pub to_network: Network,
}

impl FinalAssemblyCircuitType {
    pub fn name(&self) -> String {
        format!(
            "from_{}_to_{}_{}_final_{}",
            self.from_network.to_string(),
            self.to_network.to_string(),
            self.aggregation_type.to_string(),
            self.round
        )
    }
}

impl scheduler::CircuitType for FinalAssemblyCircuitType {
    fn name(&self) -> String {
        self.name()
    }
    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        AggregationConfigPinning::from_path(pinning_path.as_ref()).degree()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum ArbitrationCircuitType {
    BlockMerkleInclusion(BlockMerkleInclusionCircuitType),
    Transaction(EthTransactionCircuitType),
    Receipt(EthReceiptCircuitType),
    TransactionReceipt(EthTransactionReceiptCircuitType),
    MdcStorage(EthStorageCircuitType),
    FinalAssembly(FinalAssemblyCircuitType),
}

impl scheduler::CircuitType for ArbitrationCircuitType {
    fn name(&self) -> String {
        match self {
            ArbitrationCircuitType::BlockMerkleInclusion(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::Transaction(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::Receipt(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::TransactionReceipt(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::MdcStorage(circuit_type) => circuit_type.name(),
            ArbitrationCircuitType::FinalAssembly(circuit_type) => circuit_type.name(),
        }
    }

    fn get_degree_from_pinning(&self, pinning_path: impl AsRef<Path>) -> u32 {
        match self {
            ArbitrationCircuitType::BlockMerkleInclusion(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }
            ArbitrationCircuitType::Transaction(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }

            ArbitrationCircuitType::Receipt(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }

            ArbitrationCircuitType::TransactionReceipt(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }

            ArbitrationCircuitType::MdcStorage(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }

            ArbitrationCircuitType::FinalAssembly(circuit_type) => {
                circuit_type.get_degree_from_pinning(pinning_path)
            }
        }
    }
}
