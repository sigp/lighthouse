use super::deposit_parameters::DepositParameters;
use super::{Hash256};

pub struct Deposit {
    pub merkle_branch: Hash256,
    pub merkle_tree_index: u64,
    pub deposit_data: DepositData
}

pub struct DepositData {
    pub deposit_parameters: DepositParameters,
    pub value: u64,
    pub timestamp: u64
}
