use crate::ForkName;
use crate::context_deserialize;
use crate::test_utils::TestRandom;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[context_deserialize(ForkName)]
pub struct PendingConsolidation {
    #[serde(with = "serde_utils::quoted_u64")]
    pub source_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub target_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PendingConsolidation);
}
