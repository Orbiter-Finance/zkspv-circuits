use std::env::set_var;

use ethers_core::types::Bytes;
use hex::FromHex;

use crate::{ArbitrumNetwork, EthereumNetwork, Network};
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::Fr,
};
use crate::rlp::builder::RlcThreadBuilder;
use crate::transaction::ethereum::EthBlockTransactionCircuit;
use crate::util::EthConfigParams;
use crate::util::helpers::get_provider;

fn get_test_circuit(
    transaction_index: u32,
    transaction_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    network: Network,
) -> EthBlockTransactionCircuit {
    let provider = get_provider(&network);
    let mut block_number = 0;
    match network {
        Network::Ethereum(EthereumNetwork::Mainnet) => {
            block_number = 0xeee246;
        }
        Network::Ethereum(EthereumNetwork::Goerli) => {
            block_number = 0x82e239;
        }
        Network::Arbitrum(ArbitrumNetwork::Mainnet) => {
            block_number = 0x82e239;
        }
        Network::Arbitrum(ArbitrumNetwork::Goerli) => {
            block_number = 0x82e239;
        }
        _ => {}
    }
    EthBlockTransactionCircuit::from_provider(&provider, block_number, transaction_index, transaction_rlp, merkle_proof, 3, network)
}

#[test]
pub fn test_2718_transaction_mpt() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let transaction_index = 1;
    let transaction_rlp = Vec::from_hex("f86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b").unwrap();

    let proof_one_str = Vec::from_hex("f90131a076a89f6eb55cebc7bd5840cdb737b4d5c4cdc7606a94b1c445f7842148752412a03fc1c0d9f1c05d03e4151a6a336bc219a7f50ce562cd7f7a9fa7af79d619ad3ca01a644d23d46541426c501f25245651fbaf7dd9ec37a271bb6085be740275de39a09180e94c8ab99675ba998f53e83f0653a9176297277b0ecea8e85a2f92658da1a0606fb70b7ec78f5782df2098b3ca8abb84edcd53716602fc50fe0701df5837bfa0b3c5fd629a5b3dba81715fbadc5d61fc6f8eb3879af88345b1883002bb56dcb4a083c546f53a64573a88f60be282b9d3f700bebadc1be0a238565a1e1b13e53359a0f62817a8ddca5592e691877da3bd0ce817043511c439857a4a5d87f866a3e59da069bb22ce547922dd6fa51aac9f28d15491060670f65bc312f4b0b29c72e3a7098080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f901f180a02c6872dde49209fa678b257bc46638147347d07ea45a0cc1e7ccdab3a6eb2ddca0707a6691268cb1e4360514141b85380dd62930ce72aa0fb30ece7dfae559ba7da00d0c6f34c6f237d0c5edcd43d6cbd0acfd901c8dd88104ade1709870cd623cdaa0c3a015f441f4013e8c54e0ebd2b7ac42e2fb3fae8ade9da7e1f39841b64d5754a03c5123d2b26b3fd1798f86f07deb8fa3bc363ebdd944d3a467347995199a0575a03e6ce4201598f0485729874a7db824de1a6103feffc0f7e55a6d7f1ecf53fc3ba072ee92a3334b67bd93681ed2e6d1af0f3450bec76fbd70f9710735b2e6866e38a068080a0e43ebb7a507d164c3c43bf1b9d7144e5e949f8cd59480259e345251d4a09c72f08c9ecafdabac19366e7fd1137da807f478d2bd07c7269dee7d85e7686aa0f4135038390a4ffc9adc21387a7ffd7703f64b6faa21eb9f775966f7eec5e903a0930ef1ce37e6af471f4a3df2a4d15d05e52353c9cc14dc833648f5e4393f0aa9a091690279d63333d52897a32689537017867813822d863c0727438335ebe93666a0ca2551fb9de3bf5e6ea98c46bea44a4fcfc9df59df91dfea4cfe4b37e0768797a0a5223397546957bf3a6891cc7d92e50843c4beb427679444be67437329cfab49a06bf38cf8e67b990084e87976b576a68f33fb44de8121eda6f30ca2486f43a61380").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f87420b871f86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];
    let input = get_test_circuit(transaction_index, transaction_rlp, merkle_proof, Network::Ethereum(EthereumNetwork::Goerli));
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);
    // println!("instance:{:?}", circuit.instance());
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}

#[test]
pub fn test_1559_transaction_mpt() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/transaction.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let transaction_index = 53;
    let transaction_rlp = Vec::from_hex("02f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();

    let proof_one_str = Vec::from_hex("f8b1a0d2b8a354f61d3d7a1fa0de1af78958094a3eed9374756cea377879edb0bc7422a0460779b6e7622dfc26dc9d87a5660dfd08a7338323d287f7d370ac1a474fbd53a03d77ff4a636303a1415da7085256e5041f36d7d0c9b97cfd6ba394b4f66e5f31a0d7e1a6ff03b18783bc4de36fd8c2122907e56de404c6eac2084432f4dacf231680808080a0e3263af8ff4c48d1b5bf85931a69ad8d759df6ef7b6507fbdb87a62547edd0238080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f8f1a0587596c6e4da70eb8697f12d5e59733bbebd14c07bbcf56aac4adbbeb903bca1a04a06b1a1d3b0ab9609f6a7776b43b730955020ac3f90bd43dff0018c895983dca04a31b06be6094943ff2f96afb092f04fd3e28a1b8138e5792187ae563ae62ff0a010ad65155d44082ba6f9c15328f24b19c8a9f42e94489d362b5e1250017e2ec0a01d76ade4e7af7470fd3d019b55ef0f49747d2bf487acd541cd3b0bfae4e2aa97a02553d6d7e11c7b21ecee4c4b7ae341e615a29efe6fb3e16de022817986a6b987a0891ad5f0c0f5ef449173e8516c8ae143edfb9ef629ce40d5346630cd7c73605e80808080808080808080").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f87920b87602f873010285020a08fb2885020a08fb2882520894a79ed52d6774259535428f2533a8420703a4078f87054e13428c955280c080a02a3222ebb694535ee03ced3a0bc75a7c37b5053be9dcccc15894e014b1fd3a81a079250a246c8846c86cc24a84d2966752d9999ab4f05b5cca98762400e0a0f813").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];
    let input = get_test_circuit(transaction_index, transaction_rlp, merkle_proof, Network::Ethereum(EthereumNetwork::Mainnet));
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(), None);
    // println!("instance:{:?}", circuit.instance());
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}