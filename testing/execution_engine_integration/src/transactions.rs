use ethers_core::types::{
    transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest, TransactionRequest,
};

// pub const DEPOSIT_CONTRACT_ADDRESS: &str = "0x4242424242424242424242424242424242424242";

#[derive(Debug)]
pub enum Transactions {
    Transfer(Address, Address),
    TransferLegacy(Address, Address),
    _DepositContractDeposit(Address),
}

/// Get a list of transactions to publish to the execution layer.
pub fn transactions(account1: Address, account2: Address) -> Vec<TypedTransaction> {
    vec![
        Transactions::Transfer(account1, account2).transaction(),
        Transactions::TransferLegacy(account1, account2).transaction(),
    ]
}

impl Transactions {
    pub fn transaction(&self) -> TypedTransaction {
        match &self {
            Self::TransferLegacy(from, to) => TransactionRequest::new()
                .from(*from)
                .to(*to)
                .value(1)
                .into(),
            Self::Transfer(from, to) => Eip1559TransactionRequest::new()
                .from(*from)
                .to(*to)
                .value(1)
                .into(),
            Self::_DepositContractDeposit(_address) => unimplemented!(),
        }
    }
}
