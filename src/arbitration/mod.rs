use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::ProvingKey,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::fs::{gen_srs, read_params},
};

use crate::util::scheduler::{SchedulerCommon, Task};

pub mod circuit_types;
pub mod final_assembly;
pub mod helper;
pub mod proof;
pub mod test;
pub mod types;

// pub struct ArbitrationScheduler <T: Task> {

//     /// Specifies if universal trusted setup should only be read (production mode) or randomly generated (UNSAFE non-production mode)
//     srs_read_only: bool,
//     /// Specifies if new proving keys should be generated or not. If `read_only` is true, then `srs_read_only` is also force to be true.
//     read_only: bool,
//     config_dir: PathBuf,
//     data_dir: PathBuf,
//     pub pkeys: RwLock<HashMap<T::CircuitType, Arc<ProvingKey<G1Affine>>>>,
//     pub degree: RwLock<HashMap<T::CircuitType, u32>>,
//     pub params: RwLock<HashMap<u32, Arc<ParamsKZG<Bn256>>>>,

// }

// impl<T: Task> SchedulerCommon for ArbitrationScheduler<T> {
//     type CircuitType = T::CircuitType;

//     fn config_dir(&self) -> &std::path::Path {
//         self.config_dir.as_path()
//     }

//     fn data_dir(&self) -> &std::path::Path {
//         self.data_dir.as_path()
//     }

//     fn pkey_readonly(&self) -> bool {
//         self.read_only
//     }

//     fn srs_readonly(&self) -> bool {
//         self.srs_read_only
//     }

//     fn get_degree(&self, circuit_type: &Self::CircuitType) -> u32 {
//         if let Some(k) = self.degree.read().unwrap().get(circuit_type) {
//             return *k;
//         }
//         let path = self.pinning_path(circuit_type);
//         let k = CircuitType::get_degree_from_pinning(circuit_type, path);
//         self.degree.write().unwrap().insert(circuit_type.clone(), k);
//         k
//     }

//     fn get_params(&self, k: u32) -> Arc<ParamsKZG<Bn256>> {
//         if let Some(params) = self.params.read().unwrap().get(&k) {
//             return Arc::clone(params);
//         }
//         let params = if self.srs_readonly() { read_params(k) } else { gen_srs(k) };
//         let params = Arc::new(params);
//         self.params.write().unwrap().insert(k, Arc::clone(&params));
//         params
//     }

//     fn get_pkey(&self, circuit_type: &Self::CircuitType) -> Option<Arc<ProvingKey<G1Affine>>> {
//         self.pkeys.read().unwrap().get(circuit_type).map(Arc::clone)
//     }

//     fn insert_pkey(&self, circuit_type: Self::CircuitType, pkey: ProvingKey<G1Affine>) {
//         self.pkeys.write().unwrap().insert(circuit_type, Arc::new(pkey));
//     }
// }
