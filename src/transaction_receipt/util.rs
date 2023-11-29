use crate::receipt::util::ReceiptConstructor;
use crate::transaction::util::TransactionConstructor;
use crate::transaction_receipt::TransactionReceiptCircuit;
use crate::util::helpers::get_provider;

#[derive(Clone, Debug)]
pub struct TransactionReceiptConstructor {
    pub eth_transaction: TransactionConstructor,
    pub eth_receipt: ReceiptConstructor,
}

impl TransactionReceiptConstructor {
    pub fn new(eth_transaction: TransactionConstructor, eth_receipt: ReceiptConstructor) -> Self {
        assert_eq!(
            eth_transaction.network, eth_receipt.network,
            "transaction and receipt networks are inconsistent"
        );
        Self { eth_transaction, eth_receipt }
    }

    pub fn get_circuit(self) -> TransactionReceiptCircuit {
        let provider = get_provider(&self.eth_transaction.network);
        TransactionReceiptCircuit::from_provider(&provider, self)
    }
}
