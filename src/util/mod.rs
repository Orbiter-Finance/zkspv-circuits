use super::Field;
use crate::{rlp::builder::RlcThreadBreakPoints, ETH_LOOKUP_BITS};
use ethers_core::{
    types::{Address, H256, U256},
    utils::keccak256,
};
use halo2_base::QuantumCell::{Existing, self};
use halo2_base::{
    gates::{
        builder::{FlexGateConfigParams, MultiPhaseThreadBreakPoints},
        flex_gate::GateStrategy,
        GateInstructions, RangeChip, RangeInstructions,
    },
    utils::{bit_length, decompose, decompose_fe_to_u64_limbs, BigPrimeField, ScalarField},
    AssignedValue, Context,
    QuantumCell::{Constant, Witness},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::halo2::aggregation::AggregationConfigParams;
use std::{
    env::{set_var, var},
    fs::File,
    iter,
    path::Path,
};
pub mod concur_var;

use concur_var::{set_var_thread_safe, var_thread_safe};
#[cfg(feature = "aggregation")]
pub mod circuit;
pub mod contract_abi;
pub mod helpers;
#[cfg(feature = "aggregation")]
pub mod scheduler;

pub mod errors;

pub(crate) const NUM_BYTES_IN_U128: usize = 16;

pub type AssignedH256<F> = [AssignedValue<F>; 2]; // H256 as hi-lo (u128, u128)

pub fn is_leaf_zero_pad(bytes: &Vec<u8>) -> bool {
    let zero_pad = vec![0u8; 32];
    return bytes == &zero_pad; 
}

pub fn get_zero_pad() -> Vec<u8> {
    let zero_pad = vec![0u8; 32];
    return zero_pad; 
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EthConfigParams {
    pub degree: u32,
    // number of SecondPhase advice columns used in RlcConfig
    pub num_rlc_columns: usize,
    // the number of advice columns in phase _ without lookup enabled that RangeConfig uses
    pub num_range_advice: Vec<usize>,
    // the number of advice columns in phase _ with lookup enabled that RangeConfig uses
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    // for keccak chip you should know the number of unusable rows beforehand
    pub unusable_rows: usize,
    pub keccak_rows_per_round: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_bits: Option<usize>,
}

impl EthConfigParams {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        serde_json::from_reader(File::open(&path).expect("path does not exist")).unwrap()
    }
}

pub trait Halo2ConfigPinning: Serialize {
    type BreakPoints;
    /// Loads configuration parameters from a file and sets environmental variables.
    fn from_path<P: AsRef<Path>>(path: P) -> Self;
    /// Loads configuration parameters into environment variables.
    fn set_var(&self);
    /// Returns break points
    fn break_points(self) -> Self::BreakPoints;
    /// Constructs `Self` from environmental variables and break points
    fn from_var(break_points: Self::BreakPoints) -> Self;
    /// Degree of the circuit, log_2(number of rows)
    fn degree(&self) -> u32;
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EthConfigPinning {
    pub params: EthConfigParams,
    pub break_points: RlcThreadBreakPoints,
}

impl Halo2ConfigPinning for EthConfigPinning {
    type BreakPoints = RlcThreadBreakPoints;

    fn from_path<P: AsRef<Path>>(path: P) -> Self {
        println!("path:{:?}", &path.as_ref());
        let pinning: Self = serde_json::from_reader(
            File::open(&path)
                .unwrap_or_else(|e| panic!("{:?} does not exist: {e:?}", path.as_ref())),
        )
        .unwrap();
        pinning.set_var();
        pinning
    }

    fn set_var(&self) {
        // set_var("ETH_CONFIG_PARAMS", serde_json::to_string(&self.params).unwrap());
        // set_var("KECCAK_ROWS", self.params.keccak_rows_per_round.to_string());
        // let bits = self.params.lookup_bits.unwrap_or(ETH_LOOKUP_BITS);
        // set_var("LOOKUP_BITS", bits.to_string());
        set_var_thread_safe("ETH_CONFIG_PARAMS", serde_json::to_string(&self.params).unwrap());
        set_var_thread_safe("KECCAK_ROWS", self.params.keccak_rows_per_round.to_string());
        let bits = self.params.lookup_bits.unwrap_or(ETH_LOOKUP_BITS);
        set_var_thread_safe("LOOKUP_BITS", bits.to_string());
    }

    fn break_points(self) -> RlcThreadBreakPoints {
        self.break_points
    }

    fn from_var(break_points: RlcThreadBreakPoints) -> Self {
        // let params: EthConfigParams =
        //     serde_json::from_str(&var("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        let params: EthConfigParams =
            serde_json::from_str(&var_thread_safe("ETH_CONFIG_PARAMS").unwrap()).unwrap();
        Self { params, break_points }
    }

    fn degree(&self) -> u32 {
        self.params.degree
    }
}

#[derive(Serialize, Deserialize)]
pub struct AggregationConfigPinning {
    pub params: AggregationConfigParams,
    pub break_points: MultiPhaseThreadBreakPoints,
}

impl Halo2ConfigPinning for AggregationConfigPinning {
    type BreakPoints = MultiPhaseThreadBreakPoints;

    fn from_path<P: AsRef<Path>>(path: P) -> Self {
        let pinning: Self = serde_json::from_reader(
            File::open(&path)
                .unwrap_or_else(|e| panic!("{:?} does not exist: {e:?}", path.as_ref())),
        )
        .unwrap();
        pinning.set_var();
        pinning
    }

    fn set_var(&self) {
        let gate_params = FlexGateConfigParams {
            k: self.params.degree as usize,
            num_advice_per_phase: vec![self.params.num_advice],
            num_lookup_advice_per_phase: vec![self.params.num_lookup_advice],
            strategy: GateStrategy::Vertical,
            num_fixed: self.params.num_fixed,
        };
        // set_var("FLEX_GATE_CONFIG_PARAMS", serde_json::to_string(&gate_params).unwrap());
        // set_var("LOOKUP_BITS", self.params.lookup_bits.to_string());
        set_var_thread_safe(
            "FLEX_GATE_CONFIG_PARAMS",
            serde_json::to_string(&gate_params).unwrap(),
        );
        set_var_thread_safe("LOOKUP_BITS", self.params.lookup_bits.to_string());
    }

    fn break_points(self) -> MultiPhaseThreadBreakPoints {
        self.break_points
    }

    fn from_var(break_points: MultiPhaseThreadBreakPoints) -> Self {
        let params: FlexGateConfigParams =
            serde_json::from_str(&var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        let lookup_bits = var("LOOKUP_BITS").unwrap().parse().unwrap();
        Self {
            params: AggregationConfigParams {
                degree: params.k as u32,
                num_advice: params.num_advice_per_phase[0],
                num_lookup_advice: params.num_lookup_advice_per_phase[0],
                num_fixed: params.num_fixed,
                lookup_bits,
            },
            break_points,
        }
    }

    fn degree(&self) -> u32 {
        self.params.degree
    }
}

pub fn get_merkle_mountain_range(leaves: &[H256], max_depth: usize) -> Vec<H256> {
    let num_leaves = leaves.len();
    let mut merkle_roots = Vec::with_capacity(max_depth + 1);
    let mut start_idx = 0;
    for depth in (0..max_depth + 1).rev() {
        if (num_leaves >> depth) & 1 == 1 {
            merkle_roots.push(h256_tree_root(&leaves[start_idx..start_idx + (1 << depth)]));
            start_idx += 1 << depth;
        } else {
            merkle_roots.push(H256::zero());
        }
    }
    merkle_roots
}

// proof_leaf_index is the index of the leaf in `leaves` for which we want to generate a proof
// leaves: [leaf_0, leaf_1,leaf_2,leaf_3], if we want the leaf_2 merkle proof, then the proof_leaf_index is 2
// return 
//      - root: the top root of the merkle tree
//      - proof: the merkle proof from bottom to top, each element is the sibling of the leaf in the tree 
//      - proof_path: Vec<bool> from bottom to top, in each tree layer, if the leaf is on the left, then push false, otherwise push true
pub fn keccak_tree_root_and_proof(mut leaves: Vec<Vec<u8>>, proof_leaf_index: u32) -> (Vec<u8>, Vec<Vec<u8>>, Vec<bool>) {
    let depth = leaves.len().ilog2();
    assert_eq!(leaves.len(), 1 << depth);
    assert_eq!((leaves.len() >= (proof_leaf_index + 1).try_into().unwrap()), true);
    let mut proof:Vec<Vec<u8>> = Vec::with_capacity(depth as usize);
    let mut proof_leaf_index = proof_leaf_index;
    let mut proof_path: Vec<bool> = Vec::with_capacity(depth as usize);
    for d in (0..depth).rev() {
        if proof_leaf_index % 2 == 0 {
            proof.push(leaves[proof_leaf_index as usize + 1].clone());
            proof_path.push(false);
        } else {
            proof.push(leaves[proof_leaf_index as usize - 1].clone());
            proof_path.push(true)
        }
        proof_leaf_index = proof_leaf_index / 2;
        for i in 0..(1 << d) {
            leaves[i] = keccak256([(&leaves[2 * i][..]), &leaves[2 * i + 1][..]].concat()).to_vec();
        }
    }
    (leaves[0].clone(), proof, proof_path)

}

// proof_leaf_index is the index of the leaf in `leaves` for which we want to generate a proof
// when we constrcut the merkle tree, on each layer, when the number of leaves is odd, we will pad the leaves with zero leave, and hash with the last leaf, hash(leaf, zero_leaf) = leaf
pub fn keccak_non_standard_merkle_tree_root_and_proof(mut leaves: Vec<Vec<u8>>, proof_leaf_index: u32) -> (Vec<u8>, Vec<Vec<u8>>, Vec<bool>){
    let mut proof: Vec<Vec<u8>> = Vec::new();
    let mut proof_path: Vec<bool> = Vec::new();
    let mut layer_length = leaves.len();
    let mut track_proof_leave_index = proof_leaf_index.clone();    
    assert_eq!((leaves.len() >= (proof_leaf_index + 1).try_into().unwrap()), true);

    let pad_leaf = vec![0u8; 32];

    loop {
        // dbg_merkle_layer(&leaves[0..layer_length].to_vec());
        let mut push_flag = 0;
        for i in (0..layer_length).step_by(2) {
            assert_eq!(track_proof_leave_index <= (layer_length - 1).try_into().unwrap(), true);
            if (i == track_proof_leave_index as usize) && (i + 1 < layer_length - 1) {
                // leaf_0, leaf_1, ... leaf_i, leaf_i+1, ... leaf_n
                // hash(leaf_i, leaf_i+1) path is left
                proof.push(leaves[i + 1].clone());
                proof_path.push(false);
                push_flag += 1;
            } else if (i + 1 == track_proof_leave_index as usize) && (i + 1 < layer_length - 1) {
                 // leaf_0, leaf_1, ... leaf_i, leaf_i+1, ... leaf_n
                // hash(leaf_i, leaf_i+1) path is right
                proof.push(leaves[i].clone());
                proof_path.push(true);
                push_flag += 1;
            } else if (i + 1 == track_proof_leave_index as usize) && (i + 1 == layer_length - 1) {
                // leaf_0, leaf_1, ... leaf_n-1, leaf_n 
                // hash(leaf_n-1, leaf_n) path is right
                proof.push(leaves[i].clone());
                proof_path.push(true);
                push_flag += 1;
            } else if (i == track_proof_leave_index as usize) && (i + 1 == layer_length - 1) {
                // leaf_0, leaf_1, ... leaf_n-1, leaf_n i=n-1
                // hash(leaf_n-1, leaf_n) path is left
                proof.push(leaves[i + 1].clone());
                proof_path.push(false);
                push_flag += 1;
            } else if (i == track_proof_leave_index as usize) && (i == layer_length - 1) {
                // leaf_0, leaf_1, ... leaf_n  i=n
                // hash(leaf_n, leaf_n+1) path is left and pad zero leaf 
                proof.push(get_zero_pad());
                proof_path.push(false);
                push_flag += 1;
            }
            
            if i == layer_length - 1 {
                // if the leaf is the last leaf, then we copy it to the top level
                leaves[i / 2] = leaves[i].clone();
            } else {
                leaves[i / 2] = keccak256([(&leaves[i][..]), &leaves[i + 1][..]].concat()).to_vec();
            }
        }
         // every layer can only push one proof
         assert_eq!(push_flag, 1);
         push_flag = 0;
        track_proof_leave_index = track_proof_leave_index / 2;
        layer_length = (layer_length + 1) / 2;
        if layer_length == 1 {
            break;
        }
    }
    // dbg_merkle_leaf(&leaves[0]);
    // dbg_merkle_layer(&proof);
    (leaves[0].clone(), proof, proof_path)
}

pub fn h256_tree_verify(root_hash: &H256, leaf: &H256, proof: &[H256], proof_path: &Vec<bool>) {
    // let mut bytes = hash.as_bytes().to_vec();
    let root_hash = root_hash.as_bytes().to_vec();
    let leaf = leaf.as_bytes().to_vec();
    let proof: Vec<Vec<u8>> = proof.iter().map(|p| p.as_bytes().to_vec()).collect();
    // let proof = vec![vec![0u8; 32]; proof.len()];

    let mut computed_root = leaf;
    assert_eq!(proof.len(), proof_path.len());
    for (proof, path) in proof.into_iter().zip(proof_path.into_iter()) {
        if *path == false {
            if ! is_leaf_zero_pad(&proof) {
                computed_root = keccak256([computed_root, proof].concat()).to_vec();
            } else {
                computed_root = computed_root;
            }
        } else {
            if ! is_leaf_zero_pad(&proof) {
                computed_root = keccak256([proof, computed_root].concat()).to_vec();
            } else {
                computed_root = computed_root;
            }
        }
    }
    assert_eq!(root_hash, computed_root)
}

pub fn h256_non_standard_tree_root_and_proof(leaves: &[H256], proof_leaf_index: u32) -> (H256, Vec<H256>, Vec<bool>) {
    assert!(!leaves.is_empty(), "leaves should not be empty");
    assert!(proof_leaf_index <= (leaves.len() - 1).try_into().unwrap(), "proof_leaf_index should be less than leaves.len()");
    let (root, proof, proof_path) = keccak_non_standard_merkle_tree_root_and_proof(leaves.iter().map(|leaf| leaf.as_bytes().to_vec()).collect() , proof_leaf_index);
    (H256::from_slice(&root), proof.iter().map(|p| H256::from_slice(&*p)).collect(), proof_path)
}

pub fn h256_tree_root_and_proof(leaves: &[H256], proof_leaf_index: u32) -> (H256, Vec<H256>, Vec<bool>) {
    assert!(!leaves.is_empty(), "leaves should not be empty");
    let depth = leaves.len().ilog2();
    assert_eq!(leaves.len(), 1 << depth);
    let (root, proof, proof_path) = keccak_tree_root_and_proof(leaves.iter().map(|leaf| leaf.as_bytes().to_vec()).collect() , proof_leaf_index);
    (H256::from_slice(&root), proof.iter().map(|p| H256::from_slice(&*p)).collect(), proof_path)
}

/// # Assumptions
/// * `leaves` should not be empty
pub fn h256_tree_root(leaves: &[H256]) -> H256 {
    assert!(!leaves.is_empty(), "leaves should not be empty");
    let depth = leaves.len().ilog2();
    assert_eq!(leaves.len(), 1 << depth);
    if depth == 0 {
        return leaves[0];
    }
    keccak256_tree_root(leaves.iter().map(|leaf| leaf.as_bytes().to_vec()).collect())
}

pub fn keccak256_tree_root(mut leaves: Vec<Vec<u8>>) -> H256 {
    assert!(leaves.len() > 1);
    let depth = leaves.len().ilog2();
    assert_eq!(leaves.len(), 1 << depth, "leaves.len() must be a power of 2");
    for d in (0..depth).rev() {
        for i in 0..(1 << d) {
            leaves[i] = keccak256([&leaves[2 * i][..], &leaves[2 * i + 1][..]].concat()).to_vec();
        }
    }
    H256::from_slice(&leaves[0])
}

pub fn u256_to_bytes32_be(input: &U256) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    input.to_big_endian(&mut bytes);
    bytes
}

// Field is has PrimeField<Repr = [u8; 32]>
/// Takes `hash` as `bytes32` and returns `(hash[..16], hash[16..])` represented as big endian numbers in the prime field
pub fn encode_h256_to_field<F: Field>(hash: &H256) -> [F; 2] {
    let mut bytes = hash.as_bytes().to_vec();
    bytes.reverse();
    // repr is in little endian
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[16..]);
    let val1 = F::from_bytes_le(&repr);
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[..16]);
    let val2 = F::from_bytes_le(&repr);
    [val1, val2]
}

pub fn dbg_merkle_layer(layer: &Vec<Vec<u8>>) {
    println!("merkle layer:");
    for i in 0..layer.len() {
        println!("{}: {:?}", i,encode_u8_vec_to_h256(&layer[i]));
    }
}

pub fn dbg_merkle_leaf(leaf: &Vec<u8>) {
    println!("merkle leaf: {:?}", encode_u8_vec_to_h256(leaf));
}

pub fn encode_u8_vec_to_h256(bytes: &Vec<u8>) -> H256 {
    let mut bytes = bytes.clone();
    // bytes.reverse();
    let mut repr = [0u8; 32];
    repr[..bytes.len()].copy_from_slice(&bytes);
    H256(repr)
}


// every leave containts 32 Fields, 
pub fn encode_merkle_tree_leaves_field_to_h256<F: Field>(fe: &[F]) -> H256 {
    assert_eq!(fe.len(), 32);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&fe[0].to_bytes_le()[..16]);
    bytes[16..].copy_from_slice(&fe[1].to_bytes_le()[..16]);
    bytes.reverse();
    H256(bytes)

}
 
pub fn decode_field_to_h256<F: Field>(fe: &[F]) -> H256 {
    assert_eq!(fe.len(), 2);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&fe[1].to_bytes_le()[..16]);
    bytes[16..].copy_from_slice(&fe[0].to_bytes_le()[..16]);
    bytes.reverse();
    H256(bytes)
}

pub fn decode_bytes_field_to_h256<F: Field>(fe: &Vec<F>) -> H256 {
    assert_eq!(fe.len(), 32);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&fe.into_iter().map(|f| f.to_bytes_le()[0]).collect_vec());
    H256(bytes)
}

pub fn encode_h256_to_bytes_field<F: Field>(input: H256) -> Vec<F> {
    let mut bytes = input.as_bytes().to_vec();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes);
    bytes.into_iter().map(|b| {
        let mut repr = [0u8; 32];
        repr[0] = b;
        F::from_bytes_le(&repr)
    }).collect()
   
}

pub fn encode_merkle_path_to_field<F: Field>(input: &[bool]) -> Vec<F> {
    input.iter().map(|b| F::from(*b as u64)).collect_vec()
}

/// Takes U256, converts to bytes32 (big endian) and returns (hash[..16], hash[16..]) represented as big endian numbers in the prime field
pub fn encode_u256_to_field<F: Field>(input: &U256) -> [F; 2] {
    let mut bytes = vec![0; 32];
    input.to_little_endian(&mut bytes);
    // repr is in little endian
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[16..]);
    let val1 = F::from_bytes_le(&repr);
    let mut repr = [0u8; 32];
    repr[..16].copy_from_slice(&bytes[..16]);
    let val2 = F::from_bytes_le(&repr);
    [val1, val2]
}

pub fn decode_field_to_u256<F: Field>(fe: &[F]) -> U256 {
    assert_eq!(fe.len(), 2);
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&fe[0].to_bytes_le()[..16]);
    bytes[..16].copy_from_slice(&fe[1].to_bytes_le()[..16]);
    U256::from_little_endian(&bytes)
}

pub fn encode_addr_to_field<F: Field>(input: &Address) -> F {
    let mut bytes = input.as_bytes().to_vec();
    bytes.reverse();
    let mut repr = [0u8; 32];
    repr[..20].copy_from_slice(&bytes);
    F::from_bytes_le(&repr)
}

pub fn decode_field_to_addr<F: Field>(fe: &F) -> Address {
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&fe.to_bytes_le()[..20]);
    bytes.reverse();
    Address::from_slice(&bytes)
}

// circuit utils:

/// Loads boolean `val` as witness and asserts it is a bit.
pub fn load_bool<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    val: bool,
) -> AssignedValue<F> {
    let bit = ctx.load_witness(F::from(val));
    gate.assert_bit(ctx, bit);
    bit
}

/// Enforces `lhs` equals `rhs` only if `cond` is true.
///
/// Assumes that `cond` is a bit.
pub fn enforce_conditional_equality<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    lhs: AssignedValue<F>,
    rhs: AssignedValue<F>,
    cond: AssignedValue<F>,
) {
    let [lhs, rhs] = [lhs, rhs].map(|x| gate.mul(ctx, x, cond));
    ctx.constrain_equal(&lhs, &rhs);
}

/// `array2d` is an array of fixed length arrays.
/// Assumes:
/// * `array2d[i].len() = array2d[j].len()` for all `i,j`.
/// * the values of `indicator` are boolean and that `indicator` has at most one `1` bit.
/// * the lengths of `array2d` and `indicator` are the same.
///
/// Returns the "dot product" of `array2d` with `indicator` as a fixed length (1d) array of length `array2d[0].len()`.
pub fn select_array_by_indicator<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    array2d: &[impl AsRef<[AssignedValue<F>]>],
    indicator: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    (0..array2d[0].as_ref().len())
        .map(|j| {
            gate.select_by_indicator(
                ctx,
                array2d.iter().map(|array_i| array_i.as_ref()[j]),
                indicator.iter().copied(),
            )
        })
        .collect()
}

/// Assumes that `bytes` have witnesses that are bytes.
pub fn bytes_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    limbs_be_to_u128(ctx, gate, bytes, 8)
}

pub(crate) fn limbs_be_to_u128<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    limbs: &[AssignedValue<F>],
    limb_bits: usize,
) -> Vec<AssignedValue<F>> {
    assert!(!limbs.is_empty(), "limbs must not be empty");
    assert_eq!(128 % limb_bits, 0);
    limbs
        .chunks(128 / limb_bits)
        .map(|chunk| {
            gate.inner_product(
                ctx,
                chunk.iter().rev().copied(),
                (0..chunk.len()).map(|idx| Constant(gate.pow_of_two()[limb_bits * idx])),
            )
        })
        .collect_vec()
}

/// Decomposes `num` into `num_bytes` bytes in big endian and constrains the decomposition holds.
///
/// Assumes `num` has value in `u64`.
pub fn num_to_bytes_be<F: ScalarField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    num: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<AssignedValue<F>> {
    let mut bytes = Vec::with_capacity(num_bytes);
    // mostly copied from RangeChip::range_check
    let pows = range.gate.pow_of_two().iter().step_by(8).take(num_bytes).map(|x| Constant(*x));
    let byte_vals =
        decompose_fe_to_u64_limbs(num.value(), num_bytes, 8).into_iter().map(F::from).map(Witness);
    let row_offset = ctx.advice.len() as isize;
    let acc = range.gate.inner_product(ctx, byte_vals, pows);
    ctx.constrain_equal(&acc, num);

    for i in (0..num_bytes - 1).rev().map(|i| 1 + 3 * i as isize).chain(iter::once(0)) {
        let byte = ctx.get(row_offset + i);
        range.range_check(ctx, byte, 8);
        bytes.push(byte);
    }
    bytes
}

/// Takes a fixed length array `bytes` and returns a length `out_len` array equal to
/// `[[0; out_len - len], bytes[..len]].concat()`, i.e., we take `bytes[..len]` and
/// zero pad it on the left.
///
/// Assumes `0 < len <= max_len <= out_len`.
pub fn bytes_be_var_to_fixed<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[AssignedValue<F>],
    len: AssignedValue<F>,
    out_len: usize,
) -> Vec<AssignedValue<F>> {
    debug_assert!(bytes.len() <= out_len);
    debug_assert!(bit_length(out_len as u64) < F::CAPACITY as usize);

    // If `bytes` is an RLP field, then `len <= bytes.len()` was already checked during `decompose_rlp_array_phase0` so we don't need to do it again:
    // range.range_check(ctx, len, bit_length(bytes.len() as u64));
    let mut padded_bytes = bytes.to_vec();
    padded_bytes.resize(out_len, padded_bytes[0]);
    // We use a barrel shifter to shift `bytes` to the right by `out_len - len` bits.
    let shift = gate.sub(ctx, Constant(gate.get_field_element(out_len as u64)), len);
    let shift_bits = gate.num_to_bits(ctx, shift, bit_length(out_len as u64));
    for (i, shift_bit) in shift_bits.into_iter().enumerate() {
        let shifted_bytes = (0..out_len)
            .map(|j| {
                if j >= (1 << i) {
                    Existing(padded_bytes[j - (1 << i)])
                } else {
                    Constant(F::zero())
                }
            })
            .collect_vec();
        padded_bytes = padded_bytes
            .into_iter()
            .zip(shifted_bytes)
            .map(|(noshift, shift)| gate.select(ctx, shift, noshift, shift_bit))
            .collect_vec();
    }
    padded_bytes
}

/// Decomposes `uint` into `num_bytes` bytes and constrains the decomposition.
/// Here `uint` can be any uint that fits into `F`.
pub fn uint_to_bytes_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    uint: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<AssignedValue<F>> {
    let mut bytes = Vec::with_capacity(num_bytes);
    // mostly copied from RangeChip::range_check
    let pows = range.gate.pow_of_two().iter().step_by(8).take(num_bytes).map(|x| Constant(*x));
    let byte_vals = decompose(uint.value(), num_bytes, 8).into_iter().map(Witness);
    let row_offset = ctx.advice.len() as isize;
    let acc = range.gate.inner_product(ctx, byte_vals, pows);
    ctx.constrain_equal(&acc, uint);

    for i in (0..num_bytes - 1).rev().map(|i| 1 + 3 * i as isize).chain(iter::once(0)) {
        let byte = ctx.get(row_offset + i);
        range.range_check(ctx, byte, 8);
        bytes.push(byte);
    }
    bytes
}

/// See [`num_to_bytes_be`] for details. Here `uint` can now be any uint that fits into `F`.
pub fn uint_to_bytes_le<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    uint: &AssignedValue<F>,
    num_bytes: usize,
) -> Vec<AssignedValue<F>> {
    let mut bytes = Vec::with_capacity(num_bytes);
    // mostly copied from RangeChip::range_check
    let pows = range.gate.pow_of_two().iter().step_by(8).take(num_bytes).map(|x| Constant(*x));
    let byte_vals = decompose(uint.value(), num_bytes, 8).into_iter().map(Witness);
    let row_offset = ctx.advice.len() as isize;
    let acc = range.gate.inner_product(ctx, byte_vals, pows);
    ctx.constrain_equal(&acc, uint);

    for i in iter::once(0).chain((0..num_bytes - 1).map(|i| 1 + 3 * i as isize)) {
        let byte = ctx.get(row_offset + i);
        range.range_check(ctx, byte, 8);
        bytes.push(byte);
    }
    bytes
}

pub fn bytes_be_to_uint<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input: &[AssignedValue<F>],
    num_bytes: usize,
) -> AssignedValue<F> {
    gate.inner_product(
        ctx,
        input[..num_bytes].iter().rev().copied(),
        (0..num_bytes).map(|idx| Constant(gate.pow_of_two()[8 * idx])),
    )
}

/// Converts a fixed length array of `u128` values into a fixed length array of big endian bytes.
pub fn u128s_to_bytes_be<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    u128s: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    u128s.iter().map(|u128| uint_to_bytes_be(ctx, range, u128, 16)).concat()
}

/// Returns 1 if all entries of `input` are zero, 0 otherwise.
pub fn is_zero_vec<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input: &[AssignedValue<F>],
) -> AssignedValue<F> {
    let is_zeros = input.iter().map(|x| gate.is_zero(ctx, *x)).collect_vec();
    let sum = gate.sum(ctx, is_zeros);
    let total_len = gate.get_field_element(input.len() as u64);
    gate.is_equal(ctx, sum, Constant(total_len))
}

// may integer overflow
pub fn get_hash_bytes_inner_product<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    leave_proof_data: &Vec<AssignedValue<F>>,
) -> AssignedValue<F> {
    let pows = gate.pow_of_two().iter().step_by(8).take(32).map(|x| Constant(*x));
    // let leave_proof = leave_proof_data.iter().map(|x| Existing(*x)).collect_vec();
    gate.inner_product(ctx, leave_proof_data.iter().map(|x| *x).collect_vec(), pows)
}

// Assumptions: bytes_a.len() == bytes_b.len() == 32
// TODO: Not finished yet!
pub fn concat_two_hash_bytes_string_to_one<F: ScalarField>(
    ctx: &mut Context<F>,
    // range: &RangeChip<F>,
    bytes_a: &[AssignedValue<F>],
    bytes_b: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>>{
    // let total_len = bytes_a.len() + bytes_b.len();
    // let a_len = bytes_a.len();
    // let b_len = bytes_a.len();
    // let mut concats_bytes_witness = [bytes_a, bytes_b].concat().to_vec().into_iter().map(|x| Existing(x));
    // let mut concats_bytes = Vec::with_capacity(bytes_a.len() + bytes_b.len());

    // let pows = range.gate.pow_of_two().iter().step_by(8).take(total_len).map(|x| Constant(*x));
    // let pows_sub = range.gate.pow_of_two().iter().step_by(8).take(total_len).map(|x| Constant(*x));

    // let acc = range.gate.inner_product(ctx, byte_vals, pows);
    return [bytes_a, bytes_b].concat();
}