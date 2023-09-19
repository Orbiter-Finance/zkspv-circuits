use crate::{
    storage::{util::get_mdc_storage_circuit, EthBlockStorageCircuit}, 
    Network, 
    track_block::{util::get_eth_track_block_circuit, EthTrackBlockCircuit}, arbitration::helper::ArbitrationTask,
};

use super::{EthScheduler};


// #[allow(clippy::large_enum_variant)]
// #[derive(Clone, Debug, AnyCircuit)]
pub enum CircuitRouter {
    
}

pub type ArbitrationScheduler = EthScheduler<ArbitrationTask>;



// a trait for arbitration, in our business, each network(Arb, OP, ZKS, Ethereum...) should have 
// their own circuit and verifiy contract
pub trait ArbitrationBus {

    // Every Network would have own tx circuit 
    fn get_cross_tx_circuit();

    // for MDC config on L1(Ethereum)
    fn get_storage_circuit(network: Network, block_number: u32) -> EthBlockStorageCircuit {
        get_mdc_storage_circuit(network, block_number)
    }
    
    // Track Block from L1(Ethereum)
    fn get_track_block_circuit(network: Network, block_number_interval: Vec<u64>) -> EthTrackBlockCircuit{
        get_eth_track_block_circuit(block_number_interval, network)
    }


    // need to proof three mdc config, tx_time as tx happened in cross chain network, block_n as the tx_time in L1 block number
    // then proof $block_{n-1}$, $block_{n}$, $block{n+1}$, so the correspond public input should contain
    // - time_{n-1}, block_{n-1}, mdc_{n-1}
    // - time_{n}, block_{n}, mdc_{n}
    // - time_{n+1}, block_{n+1}, mdc_{n}
    // mdc: {token_address, min_amt, max_amt, repay_time, exp_time}
    // so on Arbitration Verify Contract, should constraint
    // 
    fn generate_mdc_continuity_proof(&self, network: Network,block_range: [u32;3]) {
       
    }

    // for Arb, Op, ZKS, Ethereum... Cross Chain Tx validation
    // public input should contain
    // - tx_block_hash
    // - tx_network_id
    // - tx_timestamp
    // - token_address
    // - transfer_amt
    // - transfer_from
    // - transfer_to
    // - L1_tx_block_num
    fn genrate_tx_proof();

    // for L1(Ethereum) block track
    // public input should contain
    // - (pre_block_num, block_{n-1})
    // - (mid_block_num, block_{n})
    // - (pos_block_num, block_{n+1})
    // - {l2_anchor_l1_block_num, block_{k}}
    fn generate_track_block_proof();

    fn agg_final_proof();

    // Every network task would have own verify contract
    fn gen_verify_contract();

    fn gen_proving_key();
}

pub struct EthereumArbitration {

}

impl EthereumArbitration {
    pub fn new() {

    }
}
