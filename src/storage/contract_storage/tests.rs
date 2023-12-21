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
        H256::from_str("0x2a8970e9042e59a9aeb9f533b3350295c4ecacd8087acc69ba0dd5271264ca2b")
            .unwrap(); // should be consistent with the value corresponding to the slot
    let ebc_current_rule_value = Vec::from_hex("f83d05820118010180808504a817c8008504a817c80089056bc75e2d6310000089056bc75e2d63100000839896808401312d00010183093a8083093a802a31").unwrap();

    let pre_proof_one_bytes = Vec::from_hex("f8518080a088620f0de6bec9c69bf686f518a9f8ea09a72470662e5436c6d412c12724798e808080808080a0b7018740411e5c20612639587dd1f7072d3002b76dbdba3426247f63c310cd1880808080808080").unwrap();
    let pre_proof_two_bytes = Vec::from_hex("f862a03ec2e18fd25dbf51e0962f9097d0a484bc24e566e48463eecd2eafea6cb62363b83ff83d05820118010180808504a817c8008504a817c80089056bc75e2d6310000089056bc75e2d63100000839896808401312d00010183093a8083093a802a31").unwrap();

    let ebc_current_rule_merkle_proof =
        vec![Bytes::from(pre_proof_one_bytes), Bytes::from(pre_proof_two_bytes)];

    let ebc_current_rule_params = EbcRuleParams {
        ebc_rule_key: ebc_current_rule_key,
        ebc_rule_root: ebc_current_rule_root,
        ebc_rule_value: ebc_current_rule_value,
        ebc_rule_merkle_proof: ebc_current_rule_merkle_proof,
        ebc_rule_pf_max_depth: 8,
    };

    //slots:
    let mdc_contract_address = "0xea5b70509e5bcbd021749db8edecfd14114bcab5".parse().unwrap();
    let manage_contract_address = "0x76fc39362ef66dad742791bde738b9b050c3cbf5".parse().unwrap();
    let mdc_rule_root_slot =
        H256::from_str("0x0477bf5c04c1a0a0050cfce51bcc843c625b57d17a704397e1c68b51eb610fe0")
            .unwrap();
    let mdc_rule_version_slot =
        H256::from_str("0x0477bf5c04c1a0a0050cfce51bcc843c625b57d17a704397e1c68b51eb610fe1")
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
        H256::from_str("0xe11a92942536b845da9a1f431f37793176a4b22e5871c079dbb83bc320163351")
            .unwrap();
    let manage_source_chain_mainnet_token_info_slot =
        H256::from_str("0xb7622ec464467933e9d8ba1aabad45f27773c64c309a64506e09f254c7298cda")
            .unwrap();
    let manage_dest_chain_mainnet_token_slot =
        H256::from_str("0xd6f07bc56892673add0a9596d9aa3acbe2c203735629965b8e871dfd748c940e")
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
            block_number: 4915533,
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
        block_number: 4915535,
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

    let input = get_test_circuit(Network::Ethereum(EthereumNetwork::Sepolia), 9927633);
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}
