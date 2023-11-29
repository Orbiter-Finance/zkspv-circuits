use ethers_core::types::{Bytes, H256};
use ethers_core::utils::keccak256;
use std::fmt::{Debug, Formatter};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::arbitration::circuit_types::{
    EthReceiptCircuitType, EthStorageCircuitType, EthTransactionCircuitType,
    EthTransactionReceiptCircuitType, FinalAssemblyCircuitType,
};
use crate::arbitration::final_assembly::FinalAssemblyType;
use crate::receipt::util::ReceiptConstructor;
use crate::receipt::EthBlockReceiptCircuit;
use crate::storage::contract_storage::util::{
    get_contracts_storage_circuit, MultiBlocksContractsStorageConstructor,
};
use crate::storage::contract_storage::ObContractsStorageCircuit;
use crate::track_block::BlockMerkleInclusionCircuit;
use crate::transaction::util::{
    get_eth_transaction_circuit, get_zksync_transaction_circuit, TransactionConstructor,
};
use crate::transaction::zksync_era::ZkSyncEraBlockTransactionCircuit;
use crate::transaction::EthTransactionType;
use crate::transaction_receipt::util::TransactionReceiptConstructor;
use crate::transaction_receipt::TransactionReceiptCircuit;
use crate::util::scheduler::CircuitType;
use crate::{
    track_block::{util::get_eth_track_block_circuit, EthTrackBlockCircuit},
    transaction::ethereum::EthBlockTransactionCircuit,
    util::{scheduler, EthConfigPinning, Halo2ConfigPinning},
    EthereumNetwork, Network,
};

use super::circuit_types::{ArbitrationCircuitType, BlockMerkleInclusionCircuitType};

pub type CrossChainNetwork = Network;

#[derive(Clone, Debug)]
pub struct BlockMerkleInclusionTask {
    pub input: BlockMerkleInclusionCircuit,
    pub network: Network,
    pub block_batch_num: u64,
    pub tree_depth: u64,
    pub block_range_length: u64,
}

impl BlockMerkleInclusionTask {
    pub fn new(
        input: BlockMerkleInclusionCircuit,
        network: Network,
        block_batch_num: u64,
        tree_depth: u64,
        block_range_length: u64,
    ) -> Self {
        Self { input, network, block_batch_num, tree_depth, block_range_length }
    }
    pub fn digest(&self) -> H256 {
        H256(keccak256(bincode::serialize(&self.input.inclusion_proof.input).unwrap()))
    }
}

impl scheduler::Task for BlockMerkleInclusionTask {
    type CircuitType = BlockMerkleInclusionCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        BlockMerkleInclusionCircuitType {
            network: self.network,
            block_batch_num: self.block_batch_num,
            tree_depth: self.tree_depth,
            block_range_length: self.block_range_length,
        }
    }

    fn name(&self) -> String {
        format!(
            "block_merkle_inclusion_tree_depth_{}_block_range_length_{}_block_batch_num_{}_{}",
            self.tree_depth,
            self.block_range_length,
            self.block_batch_num,
            self.digest()
        )
    }

    fn dependencies(&self) -> Vec<Self> {
        vec![]
    }
}

/// Transaction
#[derive(Clone, Debug)]
pub struct EthTransactionTask {
    pub input: EthBlockTransactionCircuit,
    pub tx_type: EthTransactionType,
    pub tasks_len: u64,
    pub constructor: Vec<TransactionConstructor>,
    pub aggregated: bool,
    pub network: Network,
}

impl EthTransactionTask {
    pub fn new(
        input: EthBlockTransactionCircuit,
        tx_type: EthTransactionType,
        tasks_len: u64,
        constructor: Vec<TransactionConstructor>,
        aggregated: bool,
        network: Network,
    ) -> Self {
        Self { input, tx_type, tasks_len, constructor, aggregated, network }
    }
    fn hash(&self) -> H256 {
        self.constructor[0].transaction_hash
    }
    fn tx_max_len(&self) -> u64 {
        self.constructor[0].tx_max_len() as u64
    }
}

impl scheduler::Task for EthTransactionTask {
    type CircuitType = EthTransactionCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthTransactionCircuitType {
            network: self.network,
            tx_type: self.tx_type.clone(),
            tasks_len: self.tasks_len,
            tx_max_len: self.tx_max_len(),
            aggregated: self.aggregated,
        }
    }

    fn name(&self) -> String {
        if self.circuit_type().is_aggregated() {
            format!(
                "transaction_aggregated_{}_task_len_{}",
                self.tx_type.to_string(),
                self.tasks_len
            )
        } else {
            format!(
                "transaction_{}_tx_{}_max_len_{}",
                self.tx_type.to_string(),
                self.hash(),
                self.tx_max_len()
            )
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructor = self.constructor.clone();
            let result = constructor
                .into_iter()
                .map(|constructor| Self {
                    input: get_eth_transaction_circuit(constructor.clone()),
                    tx_type: self.tx_type.clone(),
                    tasks_len: 1u64,
                    constructor: [constructor].to_vec(),
                    aggregated: false,
                    network: self.network,
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZkSyncTransactionTask {
    pub input: ZkSyncEraBlockTransactionCircuit,
    pub tx_type: EthTransactionType,
    pub tasks_len: u64,
    pub constructor: Vec<TransactionConstructor>,
    pub aggregated: bool,
    pub network: Network,
}

impl ZkSyncTransactionTask {
    pub fn new(
        input: ZkSyncEraBlockTransactionCircuit,
        tx_type: EthTransactionType,
        tasks_len: u64,
        constructor: Vec<TransactionConstructor>,
        aggregated: bool,
        network: Network,
    ) -> Self {
        Self { input, tx_type, tasks_len, constructor, aggregated, network }
    }
    fn hash(&self) -> H256 {
        self.constructor[0].transaction_hash
    }
    fn tx_max_len(&self) -> u64 {
        789
    }
}

impl scheduler::Task for ZkSyncTransactionTask {
    type CircuitType = EthTransactionCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthTransactionCircuitType {
            network: self.network,
            tx_type: self.tx_type.clone(),
            tasks_len: self.tasks_len,
            tx_max_len: self.tx_max_len(),
            aggregated: self.aggregated,
        }
    }

    fn name(&self) -> String {
        if self.circuit_type().is_aggregated() {
            format!(
                "zksync_era_transaction_aggregated_{}_task_len_{}",
                self.tx_type.to_string(),
                self.tasks_len
            )
        } else {
            format!(
                "zksync_era_transaction_{}_tx_{}_max_len_{}",
                self.tx_type.to_string(),
                self.hash(),
                self.tx_max_len()
            )
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructor = self.constructor.clone();
            let result = constructor
                .into_iter()
                .map(|constructor| Self {
                    input: get_zksync_transaction_circuit(constructor.clone()),
                    tx_type: self.tx_type.clone(),
                    tasks_len: 1u64,
                    constructor: [constructor].to_vec(),
                    aggregated: false,
                    network: self.network,
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

/// Transaction
#[derive(Clone, Debug)]
pub struct EthReceiptTask {
    pub input: EthBlockReceiptCircuit,
    pub constructor: Vec<ReceiptConstructor>,
    pub aggregated: bool,
    pub network: Network,
}

impl EthReceiptTask {
    pub fn new(
        input: EthBlockReceiptCircuit,
        constructor: Vec<ReceiptConstructor>,
        aggregated: bool,
        network: Network,
    ) -> Self {
        Self { input, constructor, aggregated, network }
    }
}

impl scheduler::Task for EthReceiptTask {
    type CircuitType = EthReceiptCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthReceiptCircuitType { network: self.network, aggregated: self.aggregated }
    }

    fn name(&self) -> String {
        if self.circuit_type().is_aggregated() {
            format!("receipt_aggregated",)
        } else {
            format!("receipt",)
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructor = self.constructor.clone();
            let result = constructor
                .into_iter()
                .map(|constructor| Self {
                    input: constructor.clone().get_circuit(),
                    constructor: [constructor].to_vec(),
                    aggregated: false,
                    network: self.network,
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

#[derive(Clone, Debug)]
pub struct EthTransactionReceiptTask {
    pub input: TransactionReceiptCircuit,
    pub tx_type: EthTransactionType,
    pub tasks_len: u64,
    pub constructor: Vec<TransactionReceiptConstructor>,
    pub aggregated: bool,
    pub network: Network,
}

impl EthTransactionReceiptTask {
    pub fn new(
        input: TransactionReceiptCircuit,
        tx_type: EthTransactionType,
        tasks_len: u64,
        constructor: Vec<TransactionReceiptConstructor>,
        aggregated: bool,
        network: Network,
    ) -> Self {
        Self { input, tx_type, tasks_len, constructor, aggregated, network }
    }
    fn hash(&self) -> H256 {
        self.constructor[0].eth_transaction.transaction_hash
    }
    fn tx_max_len(&self) -> u64 {
        self.constructor[0].eth_transaction.tx_max_len() as u64
    }
}

impl scheduler::Task for EthTransactionReceiptTask {
    type CircuitType = EthTransactionReceiptCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthTransactionReceiptCircuitType {
            network: self.network,
            tx_type: self.tx_type.clone(),
            tasks_len: self.tasks_len,
            tx_max_len: self.tx_max_len(),
            aggregated: self.aggregated,
        }
    }

    fn name(&self) -> String {
        if self.circuit_type().is_aggregated() {
            format!(
                "transaction_receipt_aggregated_{}_task_len_{}",
                self.tx_type.to_string(),
                self.tasks_len
            )
        } else {
            format!(
                "transaction_receipt_{}_tx_{}_max_len_{}",
                self.tx_type.to_string(),
                self.hash(),
                self.tx_max_len()
            )
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructor = self.constructor.clone();
            let result = constructor
                .into_iter()
                .map(|constructor| Self {
                    input: constructor.clone().get_circuit(),
                    tx_type: self.tx_type.clone(),
                    tasks_len: 1u64,
                    constructor: [constructor].to_vec(),
                    aggregated: false,
                    network: self.network,
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum TransactionInput {
    EthereumTx(),
}

#[derive(Clone, Debug)]
pub struct MDCStateTask {
    pub input: ObContractsStorageCircuit,
    pub single_block_include_contracts: u64,
    pub multi_blocks_number: u64,
    pub constructor: Vec<MultiBlocksContractsStorageConstructor>,
    pub aggregated: bool,
}

impl MDCStateTask {
    pub fn new(
        input: ObContractsStorageCircuit,
        single_block_include_contracts: u64,
        multi_blocks_number: u64,
        constructor: Vec<MultiBlocksContractsStorageConstructor>,
        aggregated: bool,
    ) -> Self {
        Self { input, single_block_include_contracts, multi_blocks_number, constructor, aggregated }
    }
}

impl scheduler::Task for MDCStateTask {
    type CircuitType = EthStorageCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        EthStorageCircuitType {
            network: self.constructor[0].network,
            single_block_include_contracts: self.single_block_include_contracts,
            multi_blocks_number: self.multi_blocks_number,
            aggregated: self.aggregated,
        }
    }

    fn name(&self) -> String {
        self.circuit_type().name()
    }

    fn dependencies(&self) -> Vec<Self> {
        if self.circuit_type().is_aggregated() {
            let constructor = self.constructor.clone();
            let result = constructor
                .into_iter()
                .map(|constructor| Self {
                    input: get_contracts_storage_circuit(constructor.clone()),
                    single_block_include_contracts: self.single_block_include_contracts,
                    multi_blocks_number: self.multi_blocks_number,
                    constructor: [constructor].to_vec(),
                    aggregated: self.aggregated,
                })
                .collect_vec();
            result
        } else {
            vec![]
        }
    }
}

#[derive(Clone, Debug)]
pub struct FinalAssemblyConstructor {
    pub eth_transaction_task: Option<EthTransactionTask>,
    pub zksync_transaction_task: Option<ZkSyncTransactionTask>,
    pub eth_receipt_task: Option<EthReceiptTask>,
    pub eth_transaction_receipt_task: Option<EthTransactionReceiptTask>,
    pub mdc_state_task: Option<MDCStateTask>,
    pub block_merkle_inclusion_task: Option<BlockMerkleInclusionTask>,
}

#[derive(Clone, Debug)]
pub struct FinalAssemblyTask {
    pub round: usize,
    pub final_assembly_type: FinalAssemblyType,
    pub from_network: Network,
    pub to_network: Network,
    pub constructor: FinalAssemblyConstructor,
}

impl FinalAssemblyTask {
    pub fn new(
        round: usize,
        final_assembly_type: FinalAssemblyType,
        from_network: Network,
        to_network: Network,
        constructor: FinalAssemblyConstructor,
    ) -> Self {
        Self { round, final_assembly_type, from_network, to_network, constructor }
    }
}

impl scheduler::Task for FinalAssemblyTask {
    type CircuitType = FinalAssemblyCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        FinalAssemblyCircuitType {
            round: self.round,
            aggregation_type: self.final_assembly_type.clone(),
            from_network: self.from_network,
            to_network: self.to_network,
        }
    }

    fn name(&self) -> String {
        self.circuit_type().name()
    }

    fn dependencies(&self) -> Vec<Self> {
        vec![]
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum ArbitrationTask {
    EthTransaction(EthTransactionTask),
    ZkSyncTransaction(ZkSyncTransactionTask),
    EthReceipt(EthReceiptTask),
    EthTransactionReceipt(EthTransactionReceiptTask),
    BlockMerkleInclusion(BlockMerkleInclusionTask),
    MDCState(MDCStateTask),
    Final(FinalAssemblyTask),
}

impl scheduler::Task for ArbitrationTask {
    type CircuitType = ArbitrationCircuitType;

    fn circuit_type(&self) -> Self::CircuitType {
        match self {
            ArbitrationTask::BlockMerkleInclusion(task) => {
                ArbitrationCircuitType::BlockMerkleInclusion(task.circuit_type())
            }
            ArbitrationTask::EthTransaction(task) => {
                ArbitrationCircuitType::Transaction(task.circuit_type())
            }
            ArbitrationTask::ZkSyncTransaction(task) => {
                ArbitrationCircuitType::Transaction(task.circuit_type())
            }
            ArbitrationTask::EthReceipt(task) => {
                ArbitrationCircuitType::Receipt(task.circuit_type())
            }
            ArbitrationTask::EthTransactionReceipt(task) => {
                ArbitrationCircuitType::TransactionReceipt(task.circuit_type())
            }
            ArbitrationTask::MDCState(task) => {
                ArbitrationCircuitType::MdcStorage(task.circuit_type())
            }
            ArbitrationTask::Final(task) => {
                ArbitrationCircuitType::FinalAssembly(task.circuit_type())
            }
        }
    }

    fn name(&self) -> String {
        match self {
            ArbitrationTask::BlockMerkleInclusion(task) => task.name(),
            ArbitrationTask::EthTransaction(task) => task.name(),
            ArbitrationTask::ZkSyncTransaction(task) => task.name(),
            ArbitrationTask::EthReceipt(task) => task.name(),
            ArbitrationTask::EthTransactionReceipt(task) => task.name(),
            ArbitrationTask::MDCState(task) => task.name(),
            ArbitrationTask::Final(task) => task.name(),
        }
    }

    fn dependencies(&self) -> Vec<Self> {
        match self {
            ArbitrationTask::EthTransaction(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::EthTransaction).collect()
            }
            ArbitrationTask::ZkSyncTransaction(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::ZkSyncTransaction).collect()
            }
            ArbitrationTask::EthReceipt(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::EthReceipt).collect()
            }
            ArbitrationTask::EthTransactionReceipt(task) => task
                .dependencies()
                .into_iter()
                .map(ArbitrationTask::EthTransactionReceipt)
                .collect(),
            ArbitrationTask::BlockMerkleInclusion(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::BlockMerkleInclusion).collect()
            }
            ArbitrationTask::MDCState(task) => {
                task.dependencies().into_iter().map(ArbitrationTask::MDCState).collect()
            }
            ArbitrationTask::Final(task) => {
                if task.circuit_type().round != 0 {
                    let mut circuit_type = task.circuit_type().clone();
                    circuit_type.round -= 1;
                    return vec![ArbitrationTask::Final(FinalAssemblyTask {
                        round: circuit_type.round,
                        ..task.clone()
                    })];
                }
                let task = task.clone();
                let mut task_array = vec![];

                if task.constructor.eth_transaction_task.is_some() {
                    task_array.push(ArbitrationTask::EthTransaction(
                        task.constructor.eth_transaction_task.unwrap(),
                    ));
                }
                if task.constructor.zksync_transaction_task.is_some() {
                    task_array.push(ArbitrationTask::ZkSyncTransaction(
                        task.constructor.zksync_transaction_task.unwrap(),
                    ));
                }
                if task.constructor.eth_receipt_task.is_some() {
                    task_array.push(ArbitrationTask::EthReceipt(
                        task.constructor.eth_receipt_task.unwrap(),
                    ));
                }
                if task.constructor.eth_transaction_receipt_task.is_some() {
                    task_array.push(ArbitrationTask::EthTransactionReceipt(
                        task.constructor.eth_transaction_receipt_task.unwrap(),
                    ));
                }
                if task.constructor.block_merkle_inclusion_task.is_some() {
                    task_array.push(ArbitrationTask::BlockMerkleInclusion(
                        task.constructor.block_merkle_inclusion_task.unwrap(),
                    ));
                }
                if task.constructor.mdc_state_task.is_some() {
                    task_array
                        .push(ArbitrationTask::MDCState(task.constructor.mdc_state_task.unwrap()));
                }
                task_array
            }
        }
    }
}
