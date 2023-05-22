pub(crate) const EIP_2718_TX_TYPE: u8 = 0x00;
pub(crate) const EIP_2930_TX_TYPE: u8 = 0x01;
pub(crate) const EIP_1559_TX_TYPE: u8 = 0x02;

// Status of the transaction
pub(crate) const TX_STATUS_SUCCESS: u8 = 1;

pub(crate) const TX_RECEIPT_FIELD: [u8; 3] = [0, 1, 2];

pub(crate) const EIP_1559_TX_TYPE_FIELD: [u8; 9] = [1, 3, 4, 5, 6, 7, 9, 10, 11];