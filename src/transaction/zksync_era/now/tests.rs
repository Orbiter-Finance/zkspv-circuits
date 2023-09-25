use std::env::set_var;
use std::str::FromStr;

use ethers_core::types::{TxHash, H256};

use crate::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use crate::rlp::builder::RlcThreadBuilder;
use crate::transaction::zksync_era::now::ZkSyncBlockTransactionCircuit;
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{Network, ZkSyncEraNetwork};

fn get_test_circuit(tx_hash: H256, network: Network) -> ZkSyncBlockTransactionCircuit {
    let provider = get_provider(&network);
    ZkSyncBlockTransactionCircuit::from_provider(&provider, tx_hash, network)
}

#[test]
pub fn test_zksync_transaction_slot() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/zksync_transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let network = Network::ZkSync(ZkSyncEraNetwork::Mainnet);

    let tx_hash =
        TxHash::from_str("0xa040db0769aeaacd51816aedf3036e16a30b815f12d4b89bb6a943d16f34cf45")
            .unwrap();
    let input = get_test_circuit(tx_hash, network);
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);

    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();

    Ok(())
}
