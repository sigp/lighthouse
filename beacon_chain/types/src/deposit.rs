use super::{Hash256};
use super::deposit_data::DepositData;

pub struct Deposit {
    pub merkle_branch: Vec<Hash256>,
    pub merkle_tree_index: u64,
    pub deposit_data: DepositData
}
