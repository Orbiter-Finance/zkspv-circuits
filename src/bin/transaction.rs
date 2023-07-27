use std::fmt::Display;
use std::path::PathBuf;
use ark_std::{end_timer, start_timer};
use clap::{Parser, ValueEnum};
use ethers_core::types::Bytes;
use hex::FromHex;
use zk_spv::{EthereumNetwork, Network};
use zk_spv::transaction::ethereum::helper::{ TransactionScheduler, TransactionTask};
use zk_spv::util::scheduler::evm_wrapper::ForEvm;
use zk_spv::util::scheduler::Scheduler;
//
// #[derive(Parser, Debug)]
// #[command(author, version, about, long_about = None)] // Read from `Cargo.toml`
// /// Generates multiple SNARKS for chains of block header hashes.
// /// Optionally does final processing to get merkle mountain range and/or produce EVM verifier contract code and calldata.
// struct Cli {
//     #[arg(short, long = "start", value_parser=maybe_hex::<u32>)]
//     start_block_number: u32,
//     #[arg(short, long = "end", value_parser=maybe_hex::<u32>)]
//     end_block_number: u32,
//     #[arg(long = "max-depth")]
//     max_depth: usize,
//     #[arg(long = "initial-depth")]
//     initial_depth: Option<usize>,
//     #[arg(long = "final", default_value_t = CliFinality::None)]
//     finality: CliFinality,
//     #[arg(long = "extra-rounds")]
//     rounds: Option<usize>,
//     #[arg(long = "calldata")]
//     calldata: bool,
//     #[cfg_attr(feature = "evm", arg(long = "create-contract"))]
//     create_contract: bool,
//     #[arg(long = "readonly")]
//     readonly: bool,
//     #[arg(long = "srs-readonly")]
//     srs_readonly: bool,
// }

#[derive(Clone, Debug, ValueEnum)]
enum CliFinality {
    /// Produces as many snarks as needed to fit the entire block number range, without any final processing.
    None,
    /// The block number range must fit within the specified max depth.
    /// Produces a single final snark with the starting & ending block numbers, previous and last block hashes,
    /// and merkle mountain range as output.
    Merkle,
    /// The block number range must fit within the specified max depth. Produces the final verifier circuit to verifier all
    /// the previous snarks in EVM. Writes the calldata to disk.
    Evm,
}

impl Display for CliFinality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        match self {
            CliFinality::None => write!(f, "none"),
            CliFinality::Merkle => write!(f, "merkle"),
            CliFinality::Evm => write!(f, "evm"),
        }
    }
}


fn main(){
    // let args = Cli::parse();
    #[cfg(feature = "production")]
        let srs_readonly = true;
    // #[cfg(not(feature = "production"))]
    //     let srs_readonly = args.srs_readonly;

    let network =  Network::Ethereum(EthereumNetwork::Goerli);

    let scheduler = TransactionScheduler::new(
        network,
        false,
        false,
        PathBuf::from("configs/transactions"),
        PathBuf::from("data/transactions"),
    );


    let transaction_index = 1;
    let transaction_rlp = Vec::from_hex("f86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b").unwrap();

    let proof_one_str = Vec::from_hex("f90131a076a89f6eb55cebc7bd5840cdb737b4d5c4cdc7606a94b1c445f7842148752412a03fc1c0d9f1c05d03e4151a6a336bc219a7f50ce562cd7f7a9fa7af79d619ad3ca01a644d23d46541426c501f25245651fbaf7dd9ec37a271bb6085be740275de39a09180e94c8ab99675ba998f53e83f0653a9176297277b0ecea8e85a2f92658da1a0606fb70b7ec78f5782df2098b3ca8abb84edcd53716602fc50fe0701df5837bfa0b3c5fd629a5b3dba81715fbadc5d61fc6f8eb3879af88345b1883002bb56dcb4a083c546f53a64573a88f60be282b9d3f700bebadc1be0a238565a1e1b13e53359a0f62817a8ddca5592e691877da3bd0ce817043511c439857a4a5d87f866a3e59da069bb22ce547922dd6fa51aac9f28d15491060670f65bc312f4b0b29c72e3a7098080808080808080").unwrap();
    let proof_one = Bytes::from(proof_one_str);

    let proof_two_str = Vec::from_hex("f901f180a02c6872dde49209fa678b257bc46638147347d07ea45a0cc1e7ccdab3a6eb2ddca0707a6691268cb1e4360514141b85380dd62930ce72aa0fb30ece7dfae559ba7da00d0c6f34c6f237d0c5edcd43d6cbd0acfd901c8dd88104ade1709870cd623cdaa0c3a015f441f4013e8c54e0ebd2b7ac42e2fb3fae8ade9da7e1f39841b64d5754a03c5123d2b26b3fd1798f86f07deb8fa3bc363ebdd944d3a467347995199a0575a03e6ce4201598f0485729874a7db824de1a6103feffc0f7e55a6d7f1ecf53fc3ba072ee92a3334b67bd93681ed2e6d1af0f3450bec76fbd70f9710735b2e6866e38a068080a0e43ebb7a507d164c3c43bf1b9d7144e5e949f8cd59480259e345251d4a09c72f08c9ecafdabac19366e7fd1137da807f478d2bd07c7269dee7d85e7686aa0f4135038390a4ffc9adc21387a7ffd7703f64b6faa21eb9f775966f7eec5e903a0930ef1ce37e6af471f4a3df2a4d15d05e52353c9cc14dc833648f5e4393f0aa9a091690279d63333d52897a32689537017867813822d863c0727438335ebe93666a0ca2551fb9de3bf5e6ea98c46bea44a4fcfc9df59df91dfea4cfe4b37e0768797a0a5223397546957bf3a6891cc7d92e50843c4beb427679444be67437329cfab49a06bf38cf8e67b990084e87976b576a68f33fb44de8121eda6f30ca2486f43a61380").unwrap();
    let proof_two = Bytes::from(proof_two_str);

    let proof_three_str = Vec::from_hex("f87420b871f86f83031bb085724c0d16e782f618945a873a4aa853302449a92d57b54378d4a50014588802c68af0bb140000802da01ca7ab64ae5515cd5902e3824a79cd497a0d92b9bf970400c118366f67b0a3cea06f66440c20b5d84be2aaab657222bcee7d27923942c5c58e8e2210c657b52f9b").unwrap();
    let proof_three = Bytes::from(proof_three_str);

    let merkle_proof: Vec<Bytes> = vec![proof_one, proof_two, proof_three];

    let block_number = 0x82e239;

    let task = TransactionTask::new(block_number, transaction_index, transaction_rlp,merkle_proof.clone(),merkle_proof.len(),network);
    scheduler.get_calldata(ForEvm(task), true);
}