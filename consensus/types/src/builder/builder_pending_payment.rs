use crate::{BuilderPendingWithdrawal, ForkName};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[context_deserialize(ForkName)]
pub struct BuilderPendingPayment {
    #[serde(with = "serde_utils::quoted_u64")]
    pub weight: u64,
    pub withdrawal: BuilderPendingWithdrawal,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderPendingPayment);
}
