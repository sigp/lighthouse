use crate::test_utils::TestRandom;
use crate::SignedBeaconBlockHeader;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Two conflicting proposals from the same proposer (validator).
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

impl ProposerSlashing {
    /// Get proposer index, assuming slashing validity has already been checked.
    pub fn proposer_index(&self) -> u64 {
        self.signed_header_1.message.proposer_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ProposerSlashing);
}
