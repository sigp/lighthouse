use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use tree_hash_derive::TreeHash;
use typenum::U33;

use crate::{core::Hash256, deposit::DepositData, fork::ForkName};

pub const DEPOSIT_TREE_DEPTH: usize = 32;

/// A deposit to potentially become a beacon chain validator.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct Deposit {
    pub proof: FixedVector<Hash256, U33>,
    pub data: DepositData,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Deposit);
}
