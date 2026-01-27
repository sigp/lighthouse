#[cfg(feature = "testing")]
use crate::test_utils::TestRandom;
use crate::{BuilderPendingWithdrawal, ForkName};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
#[cfg(feature = "testing")]
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "testing", derive(TestRandom))]
#[derive(
    Debug, Default, PartialEq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash,
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
