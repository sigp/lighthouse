use crate::test_utils::TestRandom;
use crate::{SignedRoot, Slot};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, Hash, Encode, Decode, TreeHash, TestRandom,
)]
pub struct SyncAggregatorSelectionData {
    pub slot: Slot,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SyncAggregatorSelectionData);
}

impl SignedRoot for SyncAggregatorSelectionData {}
