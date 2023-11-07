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
    EbcRuleParams, SingleBlockContractStorageConstructor, SingleBlockContractsStorageConstructor,
};
use crate::util::helpers::{calculate_mk_address_struct, get_provider};
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

    // ebc_rule_mpt
    let ebc_rule_key =
        H256::from_str("0xb824d67a08c69bc4f694666c7088b5d8eb3151c09000db345a9759f46dc179be")
            .unwrap();
    let ebc_rule_root =
        H256::from_str("0x407857a3d36724da1c9af7cf6cadaa4599f7c2499eda48eace754961c75fbaff")
            .unwrap(); // should be consistent with the value corresponding to the slot
    let ebc_rule_value = Vec::from_hex("f841058308274f010180808701c6bf52634c358809b6e64a8ecbf5e18701c6bf52634005880b1a2bc2ec503d0987038d7ea51bf30087038d7ea53d84c00102211c1b1e").unwrap();

    let proof_one_bytes = Vec::from_hex("f867a120b824d67a08c69bc4f694666c7088b5d8eb3151c09000db345a9759f46dc179beb843f841058308274f010180808701c6bf52634c358809b6e64a8ecbf5e18701c6bf52634005880b1a2bc2ec503d0987038d7ea51bf30087038d7ea53d84c00102211c1b1e").unwrap();
    let proof_one = Bytes::from(proof_one_bytes);

    let ebc_rule_merkle_proof = vec![proof_one];

    let ebc_rule_params = EbcRuleParams {
        ebc_rule_key,
        ebc_rule_root,
        ebc_rule_value,
        ebc_rule_merkle_proof,
        ebc_rule_pf_max_depth: 8,
    };

    // slots:
    let addr = "0x5A295a98bD9FCa8784D98c98f222B7BA52367470".parse().unwrap(); // for test

    let root_slot =
        H256::from_str("0xbb01b056691692273b8d0c6bed43fbc90e57d25c4eb695038e7b6a6c4a7b5b4d")
            .unwrap();
    let version_slot =
        H256::from_str("0xbb01b056691692273b8d0c6bed43fbc90e57d25c4eb695038e7b6a6c4a7b5b4e")
            .unwrap();
    let enable_time_slot =
        H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let slots = vec![root_slot, version_slot, enable_time_slot];
    let single_block_contract_storage_constructor = SingleBlockContractStorageConstructor {
        contract_address: addr,
        slots,
        acct_pf_max_depth: 9,
        storage_pf_max_depth: 8,
    };
    let single_block_contracts_storage_constructor = SingleBlockContractsStorageConstructor {
        block_number,
        block_contracts_storage: vec![
            single_block_contract_storage_constructor.clone(),
            single_block_contract_storage_constructor.clone(),
        ],
        ebc_rule_params,
    };
    let constructor = MultiBlocksContractsStorageConstructor {
        blocks_contracts_storage: vec![
            single_block_contracts_storage_constructor.clone(),
            single_block_contracts_storage_constructor,
        ],
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
