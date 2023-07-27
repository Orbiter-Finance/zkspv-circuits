use halo2_base::{AssignedValue, Context};
use zkevm_keccak::util::eth_types::Field;

pub mod ethereum;
pub mod zksync_era;

// The bytecode for EIP_2718_TX_TYPE is f8
const EIP_2718_TX_TYPE_INTERNAL: u8 = 0xf8;
pub const EIP_2718_TX_TYPE: u8 = 0x00;
pub const EIP_2930_TX_TYPE: u8 = 0x01;
pub const EIP_1559_TX_TYPE: u8 = 0x02;

pub const NOT_SUPPORT_TX_TYPE: i8 = -0x01;

pub const EIP_2718_TX_TYPE_FIELDS_NUM :usize = 9;
pub const EIP_1559_TX_TYPE_FIELDS_NUM:usize = 12;

pub const EIP_2718_TX_TYPE_FIELDS_ITEM: [u8; EIP_2718_TX_TYPE_FIELDS_NUM] = [0, 1, 2, 3, 4, 5, 6, 7, 8];
pub const EIP_1559_TX_TYPE_FIELDS_ITEM: [u8; EIP_2718_TX_TYPE_FIELDS_NUM] = [1, 3, 4, 5, 6, 7, 9, 10, 11];

pub const EIP_2718_TX_TYPE_FIELDS_MAX_FIELDS_LEN:[usize;EIP_2718_TX_TYPE_FIELDS_NUM] = [32, 32, 32, 20, 32, 0, 32, 32, 32];


/// Get the transaction type and validate its support.
pub fn get_transaction_type<F: Field>(ctx: &mut Context<F>, value: &AssignedValue<F>) -> u8 {
    let eip_1559_prefix = (F::from(EIP_1559_TX_TYPE as u64)).try_into().unwrap();
    let eip_1559_prefix = ctx.load_witness(eip_1559_prefix);
    let eip_2718_prefix = (F::from(EIP_2718_TX_TYPE_INTERNAL as u64)).try_into().unwrap();
    let eip_2718_prefix = ctx.load_witness(eip_2718_prefix);
    let eip_2930_prefix = (F::from(EIP_2930_TX_TYPE as u64)).try_into().unwrap();
    let eip_2930_prefix = ctx.load_witness(eip_2930_prefix);
    let transaction_type =
        if value.value == eip_1559_prefix.value {
            EIP_1559_TX_TYPE as i8
        } else if value.value == eip_2930_prefix.value {
            EIP_2930_TX_TYPE as i8
        } else if value.value == eip_2718_prefix.value {
            EIP_2718_TX_TYPE as i8 } else { NOT_SUPPORT_TX_TYPE };
    assert_ne!(transaction_type, NOT_SUPPORT_TX_TYPE, "this transaction type is not support");
    transaction_type as u8
}

// pub fn calculate_max_field_lens()