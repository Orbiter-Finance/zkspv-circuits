#![feature(int_log)]
#![feature(trait_alias)]
#![feature(return_position_impl_trait_in_trait)]
#![allow(incomplete_features)]
#![feature(thread_id_value)]

extern crate core;

use ark_std::{end_timer, start_timer};
use std::env::{set_var, var};

use halo2_base::gates::builder::{CircuitBuilderStage, MultiPhaseThreadBreakPoints};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, RangeChip},
    halo2_proofs::{
        self,
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    AssignedValue,
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
pub use zkevm_keccak::util::eth_types::Field;
use zkevm_keccak::KeccakConfig;

use crate::Network::{Arbitrum, Ethereum, Optimism, ZkSync};
use keccak::{FnSynthesize, KeccakCircuitBuilder, SharedKeccakChip};
pub use mpt::EthChip;
use util::concur_var::{set_var_thread_safe, var_thread_safe};
use util::EthConfigParams;

use crate::rlp::{
    builder::{RlcThreadBreakPoints, RlcThreadBuilder},
    rlc::RlcConfig,
    RlpConfig,
};
use crate::util::errors::ErrorType;

pub mod keccak;
pub mod mpt;
pub mod rlp;

pub mod arbitration;
pub mod block_header;
pub mod receipt;
pub mod storage;
pub mod track_block;
pub mod transaction;

pub mod config;
pub mod ecdsa;
mod gen;
#[cfg(feature = "providers")]
pub mod providers;
pub mod server;
pub mod util;

pub(crate) const ETH_LOOKUP_BITS: usize = 8; // always want 8 to range check bytes
pub(crate) const ETH_LIMB_BITS: usize = 88;
pub(crate) const ETH_NUM_LIMBS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum EthereumNetwork {
    Mainnet = 1,
    Goerli = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ArbitrumNetwork {
    Mainnet = 42161,
    Goerli = 421613,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum OptimismNetwork {
    Mainnet = 10,
    Goerli = 420,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ZkSyncEraNetwork {
    Mainnet = 324,
    Goerli = 280,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
// #[cfg_attr(feature = "clap", circuit_derive(clap::ValueEnum))]
pub enum Network {
    Ethereum(EthereumNetwork),
    Arbitrum(ArbitrumNetwork),
    Optimism(OptimismNetwork),
    ZkSync(ZkSyncEraNetwork),
}

impl Network {
    pub fn is_l1(&self) -> bool {
        matches!(self, Network::Ethereum(_))
    }
}

impl ToString for Network {
    fn to_string(&self) -> String {
        match self {
            Ethereum(_) => String::from("ethereum"),
            Arbitrum(_) => String::from("arbitrum"),
            Optimism(_) => String::from("optimism"),
            ZkSync(_) => String::from("zksync_era"),
        }
    }
}

pub fn get_network_from_chain_id(chain_id: u64) -> Result<Network, ErrorType> {
    match chain_id {
        1 => Ok(Ethereum(EthereumNetwork::Mainnet)),
        5 => Ok(Ethereum(EthereumNetwork::Goerli)),
        42161 => Ok(Arbitrum(ArbitrumNetwork::Mainnet)),
        421613 => Ok(Arbitrum(ArbitrumNetwork::Goerli)),
        10 => Ok(Optimism(OptimismNetwork::Mainnet)),
        420 => Ok(Optimism(OptimismNetwork::Goerli)),
        324 => Ok(ZkSync(ZkSyncEraNetwork::Mainnet)),
        280 => Ok(ZkSync(ZkSyncEraNetwork::Goerli)),
        _ => Err(ErrorType::NetworkNotSupported),
    }
}

#[test]
fn test_n() {
    println!("N:{:?}", Ethereum(EthereumNetwork::Goerli).to_string());
}

#[derive(Clone, Debug)]
pub struct MPTConfig<F: Field> {
    pub rlp: RlpConfig<F>,
    pub keccak: KeccakConfig<F>,
}

impl<F: Field> MPTConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: EthConfigParams) -> Self {
        let degree = params.degree;
        let mut rlp = RlpConfig::configure(
            meta,
            params.num_rlc_columns,
            &params.num_range_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits.unwrap_or(ETH_LOOKUP_BITS),
            degree as usize,
        );
        // set_var("KECCAK_DEGREE", degree.to_string());
        // set_var("KECCAK_ROWS", params.keccak_rows_per_round.to_string());
        // let keccak = KeccakConfig::new(meta, rlp.rlc.gamma);
        // set_var("UNUSABLE_ROWS", meta.minimum_rows().to_string());
        // #[cfg(feature = "display")]
        // println!("Unusable rows: {}", meta.minimum_rows());
        // rlp.range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        // Self { rlp, keccak }
        set_var_thread_safe("KECCAK_DEGREE", degree.to_string());
        set_var_thread_safe("KECCAK_ROWS", params.keccak_rows_per_round.to_string());
        let keccak = KeccakConfig::new(meta, rlp.rlc.gamma);
        set_var_thread_safe("UNUSABLE_ROWS", meta.minimum_rows().to_string());
        #[cfg(feature = "display")]
        println!("Unusable rows: {}", meta.minimum_rows());
        rlp.range.gate.max_rows = (1 << degree) - meta.minimum_rows();
        Self { rlp, keccak }
    }
}

#[derive(Clone, Debug)]
/// Config shared for block header and storage proof circuits
pub struct EthConfig<F: Field> {
    mpt: MPTConfig<F>,
    pub instance: Column<Instance>,
}

impl<F: Field> EthConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, params: impl Into<EthConfigParams>) -> Self {
        let mpt = MPTConfig::configure(meta, params.into());
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self { mpt, instance }
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        &self.mpt.rlp.range.gate
    }
    pub fn range(&self) -> &RangeConfig<F> {
        &self.mpt.rlp.range
    }
    pub fn rlc(&self) -> &RlcConfig<F> {
        &self.mpt.rlp.rlc
    }
    pub fn rlp(&self) -> &RlpConfig<F> {
        &self.mpt.rlp
    }
    pub fn keccak(&self) -> &KeccakConfig<F> {
        &self.mpt.keccak
    }
    pub fn mpt(&self) -> &MPTConfig<F> {
        &self.mpt
    }
}

/// This is an extension of [`KeccakCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that [`KeccakCircuitBuilder`] is constructed and populated. In the process, the builder produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
pub struct EthCircuitBuilder<F: Field, FnPhase1: FnSynthesize<F>> {
    pub circuit: KeccakCircuitBuilder<F, FnPhase1>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: Field, FnPhase1: FnSynthesize<F>> EthCircuitBuilder<F, FnPhase1> {
    pub fn new(
        assigned_instances: Vec<AssignedValue<F>>,
        builder: RlcThreadBuilder<F>,
        keccak: SharedKeccakChip<F>,
        range: RangeChip<F>,
        break_points: Option<RlcThreadBreakPoints>,
        synthesize_phase1: FnPhase1,
    ) -> Self {
        Self {
            assigned_instances,
            circuit: KeccakCircuitBuilder::new(
                builder,
                keccak,
                range,
                break_points,
                synthesize_phase1,
            ),
        }
    }

    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> EthConfigParams {
        self.circuit.config(k, minimum_rows)
    }

    pub fn break_points(&self) -> RlcThreadBreakPoints {
        self.circuit.break_points.borrow().clone()
    }

    pub fn instance_count(&self) -> usize {
        self.assigned_instances.len()
    }

    pub fn instance(&self) -> Vec<F> {
        self.assigned_instances.iter().map(|v| *v.value()).collect()
    }
}

impl<F: Field, FnPhase1: FnSynthesize<F>> Circuit<F> for EthCircuitBuilder<F, FnPhase1> {
    type Config = EthConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // let params: EthConfigParams =
        //     serde_json::from_str(&var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        // EthConfig::configure(meta, params)
        let params: EthConfigParams =
            serde_json::from_str(&var_thread_safe("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        EthConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = self.circuit.builder.borrow().witness_gen_only();
        let assigned_advices = self.circuit.two_phase_synthesize(&config.mpt, &mut layouter);

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "aggregation")]
impl<F: Field, FnPhase1: FnSynthesize<F>> snark_verifier_sdk::CircuitExt<F>
    for EthCircuitBuilder<F, FnPhase1>
{
    fn num_instance(&self) -> Vec<usize> {
        vec![self.instance_count()]
    }
    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instance()]
    }
}

/// Trait for objects that can be used to create an [`EthCircuitBuilder`] instantiation.
pub trait EthPreCircuit: Sized {
    /// Creates a circuit without auto-configuring it.
    fn create(
        self,
        builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>>;

    /// If feature 'production' is on, this is the same as `create`. Otherwise, it will read `ETH_CONFIG_PARAMS`
    /// from the environment to determine the desired circuit degree and number of unusable rows and then auto-configure
    /// the circuit and set environmental variables.
    fn create_circuit(
        self,
        builder: RlcThreadBuilder<Fr>,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let prover = builder.witness_gen_only();
        #[cfg(feature = "display")]
        let start = start_timer!(|| "EthPreCircuit: create_circuit");
        let circuit = self.create(builder, break_points);
        #[cfg(feature = "display")]
        end_timer!(start);
        #[cfg(not(feature = "production"))]
        if !prover {
            // let config_params: EthConfigParams = serde_json::from_str(
            //     var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
            // )
            // .unwrap();
            // circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
            let config_params: EthConfigParams = serde_json::from_str(
                var_thread_safe("ETH_CONFIG_PARAMS")
                    .expect("ETH_CONFIG_PARAMS is not set")
                    .as_str(),
            )
            .unwrap();
            circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
        }
        circuit
    }
}

/// Trait for objects that can be used to create a [`RangeWithInstanceCircuitBuilder`] instantiation.
pub trait AggregationPreCircuit: Sized {
    /// Creates a circuit without auto-configuring it.
    ///
    /// `params` should be the universal trusted setup for the present aggregation circuit.
    /// We assume the trusted setup for the previous SNARKs is compatible with `params` in the sense that
    /// the generator point and toxic waste `tau` are the same.
    fn create(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> AggregationCircuit;

    /// If feature 'production' is on, this is the same as `create`. Otherwise, it will determine the desired
    /// circuit degree from `params.k()` and auto-configure the circuit and set environmental variables.
    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> AggregationCircuit {
        #[cfg(feature = "display")]
        let start = start_timer!(|| "AggregationPreCircuit: create_circuit");
        let circuit = self.create(stage, break_points, lookup_bits, params);
        #[cfg(feature = "display")]
        end_timer!(start);
        #[cfg(not(feature = "production"))]
        if stage != CircuitBuilderStage::Prover {
            // let minimum_rows = var("UNUSABLE_ROWS").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
            // circuit.config(params.k(), Some(minimum_rows));
            let minimum_rows =
                var_thread_safe("UNUSABLE_ROWS").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
            circuit.config(params.k(), Some(minimum_rows));
        }
        circuit
    }
}
