use std::env::set_var;
use ethers_core::types::{Address, Bytes, H256};
use ethers_providers::{Http, Provider};
use rlp::RlpStream;
use tokio::runtime::Runtime;
use crate::mpt::MPTUnFixedKeyInput;
use crate::Network;
use crate::providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL};
use crate::rlp::builder::RlcThreadBuilder;
use crate::transaction::{EthBlockTransactionCircuit, EthBlockTransactionInput, EthTransactionInput};
use crate::util::EthConfigParams;
use crate::halo2_proofs::{
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
};


fn get_test_circuit(
    transaction_index: u32,
    transaction_rlp: Vec<u8>,
    merkle_proof: Vec<Bytes>,
    network: Network
) -> EthBlockTransactionCircuit {
    let infura_id = "870df3c2a62e4b8a81d466ef1b1cbefd";
    let provider_url = match network {
        Network::Mainnet => format!("{MAINNET_PROVIDER_URL}{infura_id}"),
        Network::Goerli => format!("{GOERLI_PROVIDER_URL}{infura_id}"),
    };
    let provider = Provider::<Http>::try_from(provider_url.as_str())
        .expect("could not instantiate HTTP Provider");
    let addr;
    let block_number;
    match network {
        Network::Mainnet => {
            // cryptopunks
            addr = "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB".parse::<Address>().unwrap();
            block_number = 16356350;
            //block_number = 0xf929e6;
        }
        Network::Goerli => {
            addr = "0xf2d1f94310823fe26cfa9c9b6fd152834b8e7849".parse::<Address>().unwrap();
            block_number = 0x713d54;
        }
    }
    EthBlockTransactionCircuit::from_provider(&provider, block_number, transaction_index,transaction_rlp, merkle_proof, 3, Network::Mainnet)
}

#[test]
pub fn test_transaction_mpt() -> Result<(), Box<dyn std::error::Error>> {
    let params = EthConfigParams::from_path("configs/tests/storage.json");
    set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
    let k = params.degree;
    let transaction_index = 1;
    let transaction_str = "0xf86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b";
    let transaction_rlp = hex::decode(&transaction_str[2..]).unwrap();

    let proof_one_str = "0xf90131a076a89f6eb55cebc7bd5840cdb737b4d5c4cdc7606a94b1c445f7842148752412a03fc1c0d9f1c05d03e4151a6a336bc219a7f50ce562cd7f7a9fa7af79d619ad3ca01a644d23d46541426c501f25245651fbaf7dd9ec37a271bb6085be740275de39a09180e94c8ab99675ba998f53e83f0653a9176297277b0ecea8e85a2f92658da1a0606fb70b7ec78f5782df2098b3ca8abb84edcd53716602fc50fe0701df5837bfa0b3c5fd629a5b3dba81715fbadc5d61fc6f8eb3879af88345b1883002bb56dcb4a083c546f53a64573a88f60be282b9d3f700bebadc1be0a238565a1e1b13e53359a0f62817a8ddca5592e691877da3bd0ce817043511c439857a4a5d87f866a3e59da069bb22ce547922dd6fa51aac9f28d15491060670f65bc312f4b0b29c72e3a7098080808080808080";
    let proof_one_bytes = hex::decode(&proof_one_str[2..]).unwrap();
    let proof_one = Bytes::from(proof_one_bytes);


    let proof_two_str = "0xf901f180a02c6872dde49209fa678b257bc46638147347d07ea45a0cc1e7ccdab3a6eb2ddca0707a6691268cb1e4360514141b85380dd62930ce72aa0fb30ece7dfae559ba7da00d0c6f34c6f237d0c5edcd43d6cbd0acfd901c8dd88104ade1709870cd623cdaa0c3a015f441f4013e8c54e0ebd2b7ac42e2fb3fae8ade9da7e1f39841b64d5754a03c5123d2b26b3fd1798f86f07deb8fa3bc363ebdd944d3a467347995199a0575a03e6ce4201598f0485729874a7db824de1a6103feffc0f7e55a6d7f1ecf53fc3ba072ee92a3334b67bd93681ed2e6d1af0f3450bec76fbd70f9710735b2e6866e38a068080a0e43ebb7a507d164c3c43bf1b9d7144e5e949f8cd59480259e345251d4a09c72f08c9ecafdabac19366e7fd1137da807f478d2bd07c7269dee7d85e7686aa0f4135038390a4ffc9adc21387a7ffd7703f64b6faa21eb9f775966f7eec5e903a0930ef1ce37e6af471f4a3df2a4d15d05e52353c9cc14dc833648f5e4393f0aa9a091690279d63333d52897a32689537017867813822d863c0727438335ebe93666a0ca2551fb9de3bf5e6ea98c46bea44a4fcfc9df59df91dfea4cfe4b37e0768797a0a5223397546957bf3a6891cc7d92e50843c4beb427679444be67437329cfab49a06bf38cf8e67b990084e87976b576a68f33fb44de8121eda6f30ca2486f43a61380";
    let proof_two_bytes = hex::decode(&proof_two_str[2..]).unwrap();
    let proof_two = Bytes::from(proof_two_bytes);


    let proof_three_str = "0xf87420b871f86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b";
    let proof_three_bytes = hex::decode(&proof_three_str[2..]).unwrap();
    let proof_three = Bytes::from(proof_three_bytes);

    let mut merkle_proof :Vec<Bytes> = Vec::new();
    merkle_proof.push(proof_one);
    merkle_proof.push(proof_two);
    merkle_proof.push(proof_three);
    let input = get_test_circuit(transaction_index, transaction_rlp, merkle_proof,Network::Mainnet);
    let circuit = input.create_circuit::<Fr>(RlcThreadBuilder::mock(),None);
    println!("instance:{:?}", circuit.instance());
    MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
    Ok(())
}