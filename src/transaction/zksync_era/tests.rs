use crate::halo2_proofs::dev::MockProver;
use crate::rlp::builder::RlcThreadBuilder;
use crate::transaction::util::TransactionConstructor;
use crate::transaction::zksync_era::ZkSyncEraBlockTransactionCircuit;
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{EthPreCircuit, Network, ZkSyncEraNetwork};
use ethers_core::types::H256;
use std::env::set_var;
use std::str::FromStr;

fn get_test_circuit(tx_hash: H256, network: Network) -> ZkSyncEraBlockTransactionCircuit {
    let provider = get_provider(&network);
    let constructor = TransactionConstructor {
        transaction_hash: tx_hash,
        transaction_index_bytes: None,
        transaction_rlp: None,
        merkle_proof: None,
        transaction_pf_max_depth: None,
        network,
    };
    ZkSyncEraBlockTransactionCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_1559_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/zksync_era_transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let tx = H256::from_str("0x508331b82868cbe0d4dcfaf123660c2cbe412216d37e62802184c2128002401e")
        .unwrap();
    let input = get_test_circuit(tx, Network::ZkSync(ZkSyncEraNetwork::Goerli));
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}
