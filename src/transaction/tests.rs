use std::env::set_var;
use crate::Network;
use crate::util::EthConfigParams;

fn get_test_circuit()

#[test]
pub fn test_transaction_mpt()->Result<(),Box<dyn std::error::Error>>{
    let params = EthConfigParams::from_path("configs/tests/storage.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let input = get_test_circuit();
}