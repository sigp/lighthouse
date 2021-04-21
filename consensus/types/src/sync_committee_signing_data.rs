use crate::test_utils::TestRandom;
use crate::{Hash256, SyncCommitteeSignature, SignedRoot, Slot};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Hash, Encode, Decode, TreeHash, TestRandom, Default)]
pub struct SyncCommitteeSigningData {
    pub slot: Slot,
    pub subcommittee_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SyncCommitteeSigningData);
}
