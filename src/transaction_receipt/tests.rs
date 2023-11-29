use crate::halo2_proofs::dev::MockProver;
use crate::receipt::util::{ReceiptConstructor, RECEIPT_PF_MAX_DEPTH};
use crate::rlp::builder::RlcThreadBuilder;
use crate::transaction::util::{TransactionConstructor, TRANSACTION_PF_MAX_DEPTH};
use crate::transaction_receipt::util::TransactionReceiptConstructor;
use crate::transaction_receipt::TransactionReceiptCircuit;
use crate::util::helpers::get_provider;
use crate::util::EthConfigParams;
use crate::{EthPreCircuit, EthereumNetwork, Network};
use ethers_core::types::{Bytes, H256};
use hex::FromHex;
use std::env::set_var;
use std::str::FromStr;

pub fn get_test_circuit(
    transaction_hash: H256,
    transaction_rlp: Vec<u8>,
    receipt_rlp: Vec<u8>,
    transaction_merkle_proof: Vec<Bytes>,
    receipt_merkle_proof: Vec<Bytes>,
    network: Network,
) -> TransactionReceiptCircuit {
    let provider = get_provider(&network);
    let transaction_constructor = TransactionConstructor::new(
        transaction_hash,
        None,
        Some(transaction_rlp),
        Some(transaction_merkle_proof),
        Some(TRANSACTION_PF_MAX_DEPTH),
        network,
    );
    let receipt_constructor = ReceiptConstructor::new(
        transaction_hash,
        None,
        receipt_rlp,
        receipt_merkle_proof,
        RECEIPT_PF_MAX_DEPTH,
        network,
    );
    let constructor =
        TransactionReceiptConstructor::new(transaction_constructor, receipt_constructor);
    TransactionReceiptCircuit::from_provider(&provider, constructor)
}

#[test]
pub fn test_eth_transaction_receipt_1559() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction_receipt.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let transaction_hash =
        H256::from_str("0x4bec5ffb56c6fe79a662d74fb937dfa1cae0183c6f51692c2aa172b32a5e801c")
            .unwrap();
    let transaction_rlp = Vec::from_hex("02f86f051b8402776a888402776aad82520894c3c7a782dda00a8e61cb9ba0ea8680bb3f3b9d108502540a5d6380c080a09fac27e94ef029391b4e9e01cf1868f7e689e8af812eb320357287eedd223f87a070b26c4261af5f38fd618827a75d9d5355edfd897b182a4d9b18a7b7c2fdf71c").unwrap();
    let receipt_rlp = Vec::from_hex("02f901090183734aedb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0").unwrap();

    let mut transaction_merkle_proof: Vec<Bytes> = vec![];
    {
        let proof_one_str = Vec::from_hex("f8d1a0870ae7f0b2ac6ad246dc21159a74c973fc096d730213efecd38f61cc3cf5fdb1a02550d0218b7441c19185538e429efc560c4742f7e7e44fdf271918080d907058a0513ec4eeb715d0625ab30dd7fa5739156e24a8d67b6193323c9d4a36504c3f11a08cd404ed78d538c019dbb9432ce22819c27c6f1701f1c2ab1504baef624181bfa0d117c68cd64476cefd4d98d95504bcc94e881f0f12592b9513fa90e4e01d867a808080a0dc5007a76b298f4754f12b92c51132113fd910b3bf5a3a6c1f6637c1fe0082e68080808080808080").unwrap();
        let proof_one = Bytes::from(proof_one_str);

        let proof_two_str = Vec::from_hex("f90211a0cfb300a291d6a92ceaeb0a3e66b4603b0db6052e3e8cbb2ff7207431b3364eb3a00786796678359c1a766d31e854217127f11576a61f55b67933f9970d946d82bca04e675f2f47b41a104735c3b1579a8fe49f24abbb90c8ed39a651257b30e687b6a0a03dd1b2e603c0da6afdfad448d0d075b3df7d2c2bbd897c9889e5b9900ae931a09f0b19abadbfde75a0a8545c4e326727e84ee205d25a4e6241c5f6d231781a90a000e43b15a7360238b33bc7ad6e3cf8d8aa4b160df9bdb9bb079079025148b8baa039dcfb2de2127fb7c7ebb9b8866700c339aa072718ccda71ae095ee2111fd5e5a0f13c1bc990d21aa187de840c43229fa178446b3c19f610c70c1d3495dbff14c5a0a987e0d4a718867e0fc40253a114f64c0f53afc4500fe073c318d0c7a43b51a5a05faed5cd073a84a25c7b6fef3114827e1d1d5f723a0ed21c314528ba81b20e7ea0dd109a15781273222a04b206874808032176f629a0712502a88defad9a9a18b1a0b1b0363d949651621b93ae6fe3f03e7cffc11bc325d467914046a0d8f290576ba0bd0059050d7cfde15f03493113e349872474d35dd3511ff59c6ec70a1aae5c26a0b24a95471c69758cc6910b87ef75c96e71792f4aa0c843cd5601b9dfc04bbf2aa075ffa73e38edbb56a79d5c34e5dac42d12712fcef22af2048a8c4641f39d792fa0f47501c78d78b16642599a0f33eccdc8a2702aa845f3ec3d917b7ea3db3241fe80").unwrap();
        let proof_two = Bytes::from(proof_two_str);

        let proof_three_str = Vec::from_hex("f87520b87202f86f051b8402776a888402776aad82520894c3c7a782dda00a8e61cb9ba0ea8680bb3f3b9d108502540a5d6380c080a09fac27e94ef029391b4e9e01cf1868f7e689e8af812eb320357287eedd223f87a070b26c4261af5f38fd618827a75d9d5355edfd897b182a4d9b18a7b7c2fdf71c").unwrap();
        let proof_three = Bytes::from(proof_three_str);

        transaction_merkle_proof = vec![proof_one, proof_two, proof_three];
    }
    let mut receipt_merkle_proof: Vec<Bytes> = vec![];
    {
        let proof_one_bytes = Vec::from_hex("f8d1a0e458cbc1ebfcd0b4405fabbac6860b9d4ab873b0c6c6a8cdc2a01ba69aaa69dfa03f3b46f9c16206394e6fbf276dbce0af723226c833c6bf2b054d2f07832e999fa04ce67daf6ebd76db8ba50e1694c58d18d83982955357bb9ec2c0cf376534ab29a03bac8ecd1b98e60e62608e2c79be30179b6356ba3be966aade8e7ec43f48fc0ea05dc6a4101fd9a6110f3e407e325e66bc2bc8bc7ed4851d2c802116b60b40ae20808080a0e9e83fae5e35e495bb379f3146056d92f744506aedb29059c695e8bc46de99ab8080808080808080").unwrap();
        let proof_one = Bytes::from(proof_one_bytes);

        let proof_two_bytes = Vec::from_hex("f90211a02604114a63bb1ff4157e609dfad285e72623569e3ae489c00654328fe391e5c5a026f9dcd8e7f12a432508173352c04ed48e8133c6a9b595c4049df6f0a093e492a08c84322035e81862ba9474b19c60a5482edee026f881874cd426d9977289a9f2a0e2f3c12bf4fc15c91f4657f198b6c8c4879a27189b34e922f4650c38572172bba02033a33d6ba37536fbb00591b43f62c2c1b68a40f130914dcabaaa114806024aa01c9dd42963fed695d1758a107465ca1bf468520055697835f8354dbfae4b3383a0bb92f2bef8b66b9d0af2d9c11c2014b1e3f317e1f4b0fe856f878604c174e0b6a004852f0e2a3ddd7898b2a3ddbc38ba4f7f79dfb41e3366ee6d5f0399ec4fd5d2a0d7b15884918721ce30cb9eb0a40c77e16d860d0959f84398942c9d4a4f0f52cfa03137832eb2571bf9233b6753332526e7ec2ecf88f00928b2849e362b271d090da02ef0982e908300aec272d116445253934f58c8fbb5dc9399cb0b38accd3a5c2ea073d90a57fcd502562755c1944d62b1be573743f0852de7e13c92e1f9922d865ca0f18dfe8d53cf7de25a650901c6db3ee1b4601b265c474001a3b19f577b925a10a0716e3d3d241a2c4e556a30f035505676dafe407030a3c3960978d150e2e9c892a0a51e21f93fc03c9ad33f0f5f84db53a25eee0a198e1d28640bed2930a57d1c5ca0ff68b688521ee71fce4bf844afae3ece2c2de9e9f5cebba472141d52bd3a609680").unwrap();
        let proof_two = Bytes::from(proof_two_bytes);

        let proof_three_bytes = Vec::from_hex("f9011120b9010d02f901090183734aedb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0").unwrap();
        let proof_three = Bytes::from(proof_three_bytes);

        receipt_merkle_proof = vec![proof_one, proof_two, proof_three];
    }
    let input = get_test_circuit(
        transaction_hash,
        transaction_rlp,
        receipt_rlp,
        transaction_merkle_proof,
        receipt_merkle_proof,
        Network::Ethereum(EthereumNetwork::Goerli),
    );
    let circuit = input.create_circuit(RlcThreadBuilder::mock(), None);
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}
