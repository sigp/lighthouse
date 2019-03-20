use super::{DepositData, Hash256};
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// A deposit to potentially become a beacon chain validator.
///
/// Spec v0.5.0
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Deposit {
    pub proof: Vec<Hash256>,
    pub index: u64,
    pub deposit_data: DepositData,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Deposit);
}
