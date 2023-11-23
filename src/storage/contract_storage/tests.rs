use std::str::FromStr;
use std::{
    env::set_var,
    fs::File,
    io::{BufReader, Write},
};

use ark_std::{end_timer, start_timer};
use circuit_derive;
use ethers_core::types::Bytes;
use ethers_core::utils::keccak256;
use halo2_base::utils::fs::gen_srs;
use hex::FromHex;
use serde::{Deserialize, Serialize};
use test_log::test;

use crate::storage::contract_storage::util::{
    EbcRuleParams, ObContractStorageConstructor, SingleBlockContractsStorageConstructor,
};
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    util::scheduler::Scheduler,
    ArbitrumNetwork, EthereumNetwork, Network,
};

use super::*;

pub fn get_test_circuit(network: Network, block_number: u32) -> ObContractsStorageCircuit {
    let provider = get_provider(&network);

    let ebc_current_rule_key =
        H256::from_str("0x2ec2e18fd25dbf51e0962f9097d0a484bc24e566e48463eecd2eafea6cb62363")
            .unwrap();
    let ebc_current_rule_root =
        H256::from_str("0xb463b593a4a1543b637326d0a5673c8432aaa127f9bbf7e3088ef6ae041097c3")
            .unwrap(); // should be consistent with the value corresponding to the slot
    let ebc_current_rule_value = Vec::from_hex("f84005820118010180808502540be4008502540be40089056bc75e2d6310000089056bc75e2d631000008502540be4008504a817c800010183093a8083093a80201f").unwrap();

    let pre_proof_one_bytes = Vec::from_hex("f866a1202ec2e18fd25dbf51e0962f9097d0a484bc24e566e48463eecd2eafea6cb62363b842f84005820118010180808502540be4008502540be40089056bc75e2d6310000089056bc75e2d631000008502540be4008504a817c800010183093a8083093a80201f").unwrap();

    let ebc_current_rule_merkle_proof = vec![Bytes::from(pre_proof_one_bytes)];

    let ebc_current_rule_params = EbcRuleParams {
        ebc_rule_key: ebc_current_rule_key,
        ebc_rule_root: ebc_current_rule_root,
        ebc_rule_value: ebc_current_rule_value,
        ebc_rule_merkle_proof: ebc_current_rule_merkle_proof,
        ebc_rule_pf_max_depth: 8,
    };

    //slots:
    let mdc_contract_address = "0xbe81b9b0f280a51765e2be5aac4f8c1e83a7328f".parse().unwrap();
    let manage_contract_address = "0xd7fc431bb74bd1c4c5493719f290f53d65142c1e".parse().unwrap();
    let mdc_rule_root_slot =
        H256::from_str("0x0a6b7347e59a23833f26d008b8a4d5849480313e50796a6eb192a53cda2fc7d5")
            .unwrap();
    let mdc_rule_version_slot =
        H256::from_str("0x0a6b7347e59a23833f26d008b8a4d5849480313e50796a6eb192a53cda2fc7d6")
            .unwrap();
    let mdc_rule_enable_time_slot =
        H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let mdc_column_array_hash_slot =
        H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
    let mdc_response_makers_hash_slot =
        H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap();
    let current_mdc_slots = vec![
        mdc_rule_root_slot,
        mdc_rule_version_slot,
        mdc_rule_enable_time_slot,
        mdc_column_array_hash_slot,
        mdc_response_makers_hash_slot,
    ];

    let current_mdc_contract_storage_constructor = ObContractStorageConstructor {
        contract_address: mdc_contract_address,
        slots: current_mdc_slots,
        acct_pf_max_depth: 9,
        storage_pf_max_depth: 8,
    };

    let manage_source_chain_info_slot =
        H256::from_str("0xb98b78633099fa36ed8b8680c4f8092689e1e04080eb9cbb077ca38a14d7e385")
            .unwrap();
    let manage_source_chain_mainnet_token_info_slot =
        H256::from_str("0x820eca3b68a924cd1c2962e3cd26e478c5e43b85c63554221c513ac78ff3a5f1")
            .unwrap();
    let manage_dest_chain_mainnet_token_slot =
        H256::from_str("0xf928a0ed87ea37f2e28392f64f84061cd2e9765b0aab413688e1386541db1a94")
            .unwrap();
    let manage_challenge_user_ratio_slot =
        H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000006")
            .unwrap();

    let current_manage_slots = vec![
        manage_source_chain_info_slot,
        manage_source_chain_mainnet_token_info_slot,
        manage_dest_chain_mainnet_token_slot,
        manage_challenge_user_ratio_slot,
    ];
    let current_manage_contract_storage_constructor = ObContractStorageConstructor {
        contract_address: manage_contract_address,
        slots: current_manage_slots,
        acct_pf_max_depth: 9,
        storage_pf_max_depth: 8,
    };
    let current_single_block_contracts_storage_constructor =
        SingleBlockContractsStorageConstructor {
            block_number: 10092192,
            block_contracts_storage: vec![
                current_mdc_contract_storage_constructor,
                current_manage_contract_storage_constructor,
            ],
        };

    let next_mdc_slots = vec![mdc_rule_version_slot, mdc_rule_enable_time_slot];
    let next_mdc_contract_storage_constructor = ObContractStorageConstructor {
        contract_address: mdc_contract_address,
        slots: next_mdc_slots,
        acct_pf_max_depth: 9,
        storage_pf_max_depth: 8,
    };
    let next_single_block_contracts_storage_constructor = SingleBlockContractsStorageConstructor {
        block_number: 10092468,
        block_contracts_storage: vec![next_mdc_contract_storage_constructor],
    };

    let constructor = MultiBlocksContractsStorageConstructor {
        blocks_contracts_storage: vec![
            current_single_block_contracts_storage_constructor,
            next_single_block_contracts_storage_constructor,
        ],
        ebc_rule_params: ebc_current_rule_params,
        network,
    };
    ObContractsStorageCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_contract_mdc_storage() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/ob_contracts_storage.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;

    let input = get_test_circuit(Network::Ethereum(EthereumNetwork::Goerli), 9927633);
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}
