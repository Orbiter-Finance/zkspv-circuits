use crate::arbitration::helper::{
    BlockMerkleInclusionTask, EthTransactionTask, FinalAssemblyConstructor, MDCStateTask,
    ZkSyncTransactionTask,
};
use crate::arbitration::network_pairs::NetworkPairs;
use crate::arbitration::types::{BatchBlocksInput, ObContractStorageInput, TransactionInput};
use crate::storage::contract_storage::util::{
    EbcRuleParams, MultiBlocksContractsStorageConstructor, ObContractStorageConstructor,
    SingleBlockContractsStorageConstructor,
};
use crate::track_block::BlockMerkleInclusionCircuit;
use crate::transaction::util::{
    get_eth_transaction_circuit, get_zksync_transaction_circuit, TransactionConstructor,
};
use crate::transaction::EthTransactionType;
use crate::util::errors::COMMIT_TRANSACTION_IS_EMPTY;
use ethers_core::types::H256;

pub fn parse_from_zksync_to_ethereum(
    pairs: &NetworkPairs,
    ob_contract_storage_input: Option<ObContractStorageInput>,
    batch_blocks_input: Option<BatchBlocksInput>,
    original_transaction: TransactionInput,
    commit_transaction: Option<TransactionInput>,
) -> FinalAssemblyConstructor {
    let (_, _, is_source) = pairs.get_details();
    let (l1_network, l2_network) = pairs.get_layer_network();

    let mut eth_transaction_task = None;
    let mut zksync_transaction_task = None;
    let mut mdc_state_task = None;
    let mut block_merkle_inclusion_task = None;

    if batch_blocks_input.is_some() {
        let batch_blocks_task_input =
            BlockMerkleInclusionCircuit::from_json_object(batch_blocks_input.unwrap());
        block_merkle_inclusion_task = Some(BlockMerkleInclusionTask::new(
            batch_blocks_task_input.clone(),
            l1_network,
            batch_blocks_task_input.block_batch_num,
            8,
            batch_blocks_task_input.block_range_length,
        ));
    }
    let mut original_transaction_constructor = TransactionConstructor::new(
        original_transaction.transaction_hash,
        Some(original_transaction.transaction_proof.key.clone()),
        Some(original_transaction.transaction_proof.value.clone()),
        Some(original_transaction.transaction_proof.proof.clone()),
        Some(original_transaction.transaction_proof.proof.clone().len()),
        l2_network,
    );

    if is_source {
        let storage_input = ob_contract_storage_input.as_ref().unwrap();

        let mdc_contract_storage_current_constructor = ObContractStorageConstructor::new(
            storage_input.mdc_address,
            storage_input.contracts_slots_hash[..5].to_vec(),
            9,
            8,
        );

        let manage_contract_storage_current_constructor = ObContractStorageConstructor::new(
            storage_input.manage_address,
            storage_input.contracts_slots_hash[5..].to_vec(),
            9,
            8,
        );

        let mdc_contract_storage_next_constructor = ObContractStorageConstructor::new(
            storage_input.mdc_address,
            storage_input.contracts_slots_hash[1..3].to_vec(),
            9,
            8,
        );

        let single_block_contracts_storage_constructor_current =
            SingleBlockContractsStorageConstructor::new(
                storage_input.mdc_current_enable_time_block_number as u32,
                vec![
                    mdc_contract_storage_current_constructor,
                    manage_contract_storage_current_constructor,
                ],
            );
        let single_block_contracts_storage_constructor_next =
            SingleBlockContractsStorageConstructor::new(
                storage_input.mdc_next_enable_time_block_number as u32,
                vec![mdc_contract_storage_next_constructor],
            );
        let ob_contracts_constructor = MultiBlocksContractsStorageConstructor::new(
            vec![
                single_block_contracts_storage_constructor_current,
                single_block_contracts_storage_constructor_next,
            ],
            EbcRuleParams::new(
                H256::from_slice(&*storage_input.mdc_current_rule.key.clone()),
                storage_input.mdc_current_rule.root.unwrap(),
                storage_input.mdc_current_rule.value.clone(),
                storage_input.mdc_current_rule.proof.clone(),
                8,
            ),
            l1_network,
        );
        mdc_state_task = Some(MDCStateTask::new(
            ob_contracts_constructor.clone().get_circuit(),
            2,
            2,
            vec![ob_contracts_constructor],
            false,
        ));

        // Todo: Currently the maximum encoding is not supported.
        // let commit_transaction = commit_transaction.expect(COMMIT_TRANSACTION_IS_EMPTY);
        // // commit tx
        // let commit_transaction_constructor = TransactionConstructor::new(
        //     commit_transaction.transaction_hash,
        //     Some(commit_transaction.transaction_proof.key.clone()),
        //     Some(commit_transaction.transaction_proof.value.clone()),
        //     Some(commit_transaction.transaction_proof.proof.clone()),
        //     Some(commit_transaction.transaction_proof.proof.clone().len()),
        //     l1_network,
        // );

        zksync_transaction_task = Some(ZkSyncTransactionTask::new(
            get_zksync_transaction_circuit(original_transaction_constructor.clone()),
            EthTransactionType::DynamicFeeTxType,
            1,
            vec![original_transaction_constructor],
            false,
            l2_network,
        ));

        // eth_transaction_task = Some(EthTransactionTask::new(
        //     get_eth_transaction_circuit(commit_transaction_constructor.clone()),
        //     EthTransactionType::DynamicFeeTxType,
        //     1,
        //     vec![commit_transaction_constructor],
        //     false,
        //     l1_network,
        // ));
    } else {
        original_transaction_constructor.network = l1_network;
        eth_transaction_task = Some(EthTransactionTask::new(
            get_eth_transaction_circuit(original_transaction_constructor.clone()),
            EthTransactionType::DynamicFeeTxType,
            1,
            vec![original_transaction_constructor],
            false,
            l1_network,
        ));
    }

    FinalAssemblyConstructor {
        eth_transaction_task,
        zksync_transaction_task,
        mdc_state_task,
        block_merkle_inclusion_task,
    }
}
