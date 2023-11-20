use halo2_base::{AssignedValue, Context};
use serde::{Deserialize, Serialize};
use zkevm_keccak::util::eth_types::Field;
pub mod ethereum;
pub mod zksync_era;

/// The theoretical maximum value of Ethereum transaction type is 7f (Except for Legacy transactions:f8) https://ethereum.org/zh/developers/docs/transactions/#typed-transaction-envelope
pub const EIP_TX_TYPE_CRITICAL_VALUE: u8 = 0x80;

/// The type of the Legacy transaction should be 0, so the first byte is f8
pub const EIP_2718_TX_TYPE: u8 = 0xf8;
pub const EIP_2930_TX_TYPE: u8 = 0x01;
pub const EIP_1559_TX_TYPE: u8 = 0x02;

const TX_INDEX_MAX_LEN: usize = 3;

const TX_DATA_MAX_LEN: usize = 512;
const TX_ACCESS_LIST_MAX_LEN: usize = 0;

pub const EIP_2718_TX_TYPE_FIELDS_NUM: usize = 9;
pub const EIP_1559_TX_TYPE_FIELDS_NUM: usize = 12;

pub const EIP_2718_TX_TYPE_FIELDS_MAX_FIELDS_LEN: [usize; EIP_2718_TX_TYPE_FIELDS_NUM] =
    [32, 32, 32, 20, 32, TX_DATA_MAX_LEN, 32, 32, 32];
pub const EIP_1559_TX_TYPE_FIELDS_MAX_FIELDS_LEN: [usize; EIP_1559_TX_TYPE_FIELDS_NUM] =
    [32, 32, 32, 32, 32, 20, 32, TX_DATA_MAX_LEN, TX_ACCESS_LIST_MAX_LEN, 1, 32, 32];

pub const TX_MAX_LEN: usize = 32 * 8 + 20 + 1 + TX_DATA_MAX_LEN + TX_ACCESS_LIST_MAX_LEN;

const FUNCTION_SELECTOR_BYTES_LEN: usize = 4;
const ERC20_TO_ADDRESS_BYTES_LEN: usize = 32;
const ERC20_AMOUNT_BYTES_LEN: usize = 32;
const FUNCTION_SELECTOR_ERC20_TRANSFER: [u8; FUNCTION_SELECTOR_BYTES_LEN] = [169, 5, 156, 187];
const CALLDATA_BYTES_LEN: usize =
    FUNCTION_SELECTOR_BYTES_LEN + ERC20_TO_ADDRESS_BYTES_LEN + ERC20_AMOUNT_BYTES_LEN;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum EthTransactionType {
    LegacyTxType,     // 0x00
    AccessListTxType, // 0x01
    DynamicFeeTxType, // 0x02
}

impl ToString for EthTransactionType {
    fn to_string(&self) -> String {
        match self {
            EthTransactionType::LegacyTxType => String::from("legacy_tx_type"),
            EthTransactionType::AccessListTxType => String::from("access_list_tx_type"),
            EthTransactionType::DynamicFeeTxType => String::from("dynamic_fee_tx_type"),
        }
    }
}

/// Assigns transaction type as a constant value and returns the corresponding assigned cell.
pub fn load_transaction_type<F: Field>(ctx: &mut Context<F>, tx_type: u8) -> AssignedValue<F> {
    let type_value = (F::from(tx_type as u64)).try_into().unwrap();
    ctx.load_constant(type_value)
}
