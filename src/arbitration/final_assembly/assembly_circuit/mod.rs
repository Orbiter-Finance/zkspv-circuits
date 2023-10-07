use crate::arbitration::final_assembly::DummyEccChip;
use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
use crate::rlp::RlpChip;
use crate::util::circuit::{PinnableCircuit, PreCircuit};
use crate::util::{EthConfigParams, EthConfigPinning, Halo2ConfigPinning};
use crate::{EthChip, EthCircuitBuilder};
use halo2_base::gates::builder::CircuitBuilderStage;
use halo2_base::gates::{RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::ProvingKey,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::fs::{gen_srs, read_params},
};
use itertools::Itertools;
use snark_verifier::loader::halo2::Halo2Loader;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::{Snark, LIMBS, SHPLONK};
use std::cell::RefCell;
use std::env::var;

// #[derive(Clone, Debug)]
// pub struct FinalAssemblyCircuit {
//     pub transaction_snark: Snark,
//     pub block_snark: Snark,
//     pub mdc_state_snark: Snark,
//
//     pub block_has_accumulator: bool,
//     pub transaction_has_accumulator: bool,
//     pub mdc_state_has_accumulator: bool,
// }

#[derive(Clone, Debug)]
pub struct FinalAssemblyCircuit {
    pub block_snark_1: Snark,
    pub block_snark_2: Snark,

    pub block_has_accumulator_1: bool,
    pub block_has_accumulator_2: bool,
}

impl FinalAssemblyCircuit {
    pub fn new(block_1: (Snark, bool), block_2: (Snark, bool)) -> Self {
        Self {
            block_snark_1: block_1.0,
            block_snark_2: block_2.0,

            block_has_accumulator_1: block_1.1,
            block_has_accumulator_2: block_2.1,
        }
    }
}

impl FinalAssemblyCircuit {
    fn create(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<RlcThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        log::info!("New FinalResponseAggregationCircuit",);
        // aggregate the snarks
        // let aggregation = AggregationCircuit::new::<SHPLONK>(
        //     stage,
        //     Some(Vec::new()), // break points aren't actually used, since we will just take the builder from this circuit
        //     lookup_bits,
        //     params,
        //     [self.transaction_snark, self.block_snark, self.mdc_state_snark],
        // );
        let aggregation = AggregationCircuit::new::<SHPLONK>(
            stage,
            Some(Vec::new()), // break points aren't actually used, since we will just take the builder from this circuit
            lookup_bits,
            params,
            [self.block_snark_1, self.block_snark_2],
        );
        // let (transaction_instance, block_instance, mdc_state_instance) = aggregation
        //     .previous_instances
        //     .iter()
        //     .zip_eq([
        //         self.transaction_has_accumulator,
        //         self.block_has_accumulator,
        //         self.mdc_state_has_accumulator,
        //     ])
        //     .map(|(instance, has_accumulator)| {
        //         let start = (has_accumulator as usize) * 4 * LIMBS;
        //         &instance[start..]
        //     })
        //     .collect_tuple()
        //     .unwrap();

        let (block_instance_1, block_instance_2) = aggregation
            .previous_instances
            .iter()
            .zip_eq([self.block_has_accumulator_1, self.block_has_accumulator_2])
            .map(|(instance, has_accumulator)| {
                let start = (has_accumulator as usize) * 4 * LIMBS;
                &instance[start..]
            })
            .collect_tuple()
            .unwrap();

        // TODO: should reuse RangeChip from aggregation circuit, but can't refactor right now
        let range = RangeChip::default(lookup_bits);
        let gate_builder = aggregation.inner.circuit.0.builder.take();
        let _chip = DummyEccChip(range.gate());

        let loader = Halo2Loader::<G1Affine, _>::new(_chip, gate_builder);

        let mut keccak = KeccakChip::default();

        let mut gate_builder = loader.take_ctx();

        let builder = RlcThreadBuilder { threads_rlc: Vec::new(), gate_builder };
        let mut assigned_instances = aggregation.inner.assigned_instances;

        EthCircuitBuilder::new(
            assigned_instances,
            builder,
            RefCell::new(keccak),
            range,
            break_points,
            |_: &mut RlcThreadBuilder<Fr>,
             _: RlpChip<Fr>,
             _: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {},
        )
    }

    pub fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        break_points: Option<RlcThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
    ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
        let circuit = self.create(stage, break_points, lookup_bits, params);
        #[cfg(not(feature = "production"))]
        if stage != CircuitBuilderStage::Prover {
            let config_params: EthConfigParams = serde_json::from_str(
                var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
            )
            .unwrap();
            circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
        }
        circuit
    }
}

impl PreCircuit for FinalAssemblyCircuit {
    type Pinning = EthConfigPinning;

    fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<Self::Pinning>,
        params: &ParamsKZG<Bn256>,
    ) -> impl PinnableCircuit<Fr> {
        // look for lookup_bits either from pinning, if available, or from env var
        let lookup_bits = pinning
            .as_ref()
            .map(|p| p.params.lookup_bits.unwrap())
            .or_else(|| var("LOOKUP_BITS").map(|v| v.parse().unwrap()).ok())
            .expect("LOOKUP_BITS is not set");
        let break_points = pinning.map(|p| p.break_points());
        FinalAssemblyCircuit::create_circuit(self, stage, break_points, lookup_bits, params)
    }
}
