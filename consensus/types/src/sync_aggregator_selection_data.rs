use crate::context_deserialize;
use crate::test_utils::TestRandom;
use crate::{ForkName, SignedRoot, Slot};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, Hash, Encode, Decode, TreeHash, TestRandom,
)]
#[context_deserialize(ForkName)]
pub struct SyncAggregatorSelectionData {
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
}

impl SignedRoot for SyncAggregatorSelectionData {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SyncAggregatorSelectionData);
}
