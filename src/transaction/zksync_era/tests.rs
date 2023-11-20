use crate::halo2_proofs::dev::MockProver;
use crate::rlp::builder::RlcThreadBuilder;
use crate::transaction::zksync_era::util::ZkSyncEraTransactionConstructor;
use crate::transaction::zksync_era::ZkSyncEraBlockTransactionCircuit;
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{EthPreCircuit, Network, ZkSyncEraNetwork};
use ethers_core::types::H256;
use std::env::set_var;
use std::str::FromStr;

fn get_test_circuit(tx_hash: H256, network: Network) -> ZkSyncEraBlockTransactionCircuit {
    let provider = get_provider(&network);
    let constructor = ZkSyncEraTransactionConstructor { transaction_hash: tx_hash, network };
    ZkSyncEraBlockTransactionCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_1559_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/zksync_era_transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let tx = H256::from_str("0x43793e2d74822b85f88eb9b2fcd771dc2a85e50091f2e2b0536fb2c796d31c5e")
        .unwrap();
    let input = get_test_circuit(tx, Network::ZkSync(ZkSyncEraNetwork::Mainnet));
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}
