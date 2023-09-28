// use crate::keccak::{FixedLenRLCs, FnSynthesize, KeccakChip, VarLenRLCs};
// use crate::rlp::builder::{RlcThreadBreakPoints, RlcThreadBuilder};
// use crate::rlp::RlpChip;
// use crate::util::EthConfigParams;
// use crate::{EthChip, EthCircuitBuilder};
// use halo2_base::gates::builder::CircuitBuilderStage;
// use halo2_base::gates::{RangeChip, RangeInstructions};
// use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
// use halo2_base::{
//     halo2_proofs::{
//         halo2curves::bn256::{Bn256, G1Affine},
//         plonk::ProvingKey,
//         poly::kzg::commitment::ParamsKZG,
//     },
//     utils::fs::{gen_srs, read_params},
// };
// use itertools::Itertools;
// use snark_verifier::loader::halo2::Halo2Loader;
// use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
// use snark_verifier_sdk::{Snark, LIMBS, SHPLONK};
// use std::cell::RefCell;
// use std::env::var;
//
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
//
// impl FinalAssemblyCircuit {
//     pub fn new(block: (Snark, bool), transaction: (Snark, bool), mdc_state: (Snark, bool)) -> Self {
//         Self {
//             transaction_snark: transaction.0,
//             block_snark: block.0,
//             mdc_state_snark: mdc_state.0,
//
//             block_has_accumulator: block.1,
//             transaction_has_accumulator: transaction.1,
//             mdc_state_has_accumulator: mdc_state.1,
//         }
//     }
// }
//
// impl FinalAssemblyCircuit {
//     fn create(
//         self,
//         stage: CircuitBuilderStage,
//         break_points: Option<RlcThreadBreakPoints>,
//         lookup_bits: usize,
//         params: &ParamsKZG<Bn256>,
//     ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
//         log::info!("New FinalResponseAggregationCircuit",);
//         // aggregate the snarks
//         let aggregation = AggregationCircuit::new::<SHPLONK>(
//             stage,
//             Some(Vec::new()), // break points aren't actually used, since we will just take the builder from this circuit
//             lookup_bits,
//             params,
//             [self.transaction_snark, self.block_snark, self.mdc_state_snark],
//         );
//         let (transaction_instance, block_instance, mdc_state_instance) = aggregation
//             .previous_instances
//             .iter()
//             .zip_eq([
//                 self.transaction_has_accumulator,
//                 self.block_has_accumulator,
//                 self.mdc_state_has_accumulator,
//             ])
//             .map(|(instance, has_accumulator)| {
//                 let start = (has_accumulator as usize) * 4 * LIMBS;
//                 &instance[start..]
//             })
//             .collect_tuple()
//             .unwrap();
//
//         // TODO: should reuse RangeChip from aggregation circuit, but can't refactor right now
//         let range = RangeChip::default(lookup_bits);
//         let gate_builder = aggregation.inner.circuit.0.builder.take();
//         let chip = EthChip::new(RlpChip::new(&range, None), None);
//         let loader = Halo2Loader::<G1Affine, _>::new(chip, gate_builder);
//
//         let mut keccak = KeccakChip::default();
//
//         let mut gate_builder = loader.take_ctx();
//
//         let builder = RlcThreadBuilder { threads_rlc: Vec::new(), gate_builder };
//         let mut assigned_instances = aggregation.inner.assigned_instances;
//
//         EthCircuitBuilder::new(
//             assigned_instances,
//             builder,
//             RefCell::new(keccak),
//             range,
//             break_points,
//             |_: &mut RlcThreadBuilder<Fr>,
//              _: RlpChip<Fr>,
//              _: (FixedLenRLCs<Fr>, VarLenRLCs<Fr>)| {},
//         )
//     }
//
//     pub fn create_circuit(
//         self,
//         stage: CircuitBuilderStage,
//         break_points: Option<RlcThreadBreakPoints>,
//         lookup_bits: usize,
//         params: &ParamsKZG<Bn256>,
//     ) -> EthCircuitBuilder<Fr, impl FnSynthesize<Fr>> {
//         let circuit = self.create(stage, break_points, lookup_bits, params);
//         #[cfg(not(feature = "production"))]
//         if stage != CircuitBuilderStage::Prover {
//             let config_params: EthConfigParams = serde_json::from_str(
//                 var("ETH_CONFIG_PARAMS").expect("ETH_CONFIG_PARAMS is not set").as_str(),
//             )
//             .unwrap();
//             circuit.config(config_params.degree as usize, Some(config_params.unusable_rows));
//         }
//         circuit
//     }
// }
