use crate::test_utils::TestRandom;
use crate::Hash256;

use crate::beacon_state::BeaconStateTypes;
use fixed_len_vec::FixedLenVec;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Historical block and state roots.
///
/// Spec v0.5.1
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
)]
pub struct HistoricalBatch<T: BeaconStateTypes> {
    pub block_roots: FixedLenVec<Hash256, T::SlotsPerHistoricalRoot>,
    pub state_roots: FixedLenVec<Hash256, T::SlotsPerHistoricalRoot>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_state::beacon_state_types::FoundationStateTypes;

    pub type FoundationHistoricalBatch = HistoricalBatch<FoundationStateTypes>;

    ssz_tests!(FoundationHistoricalBatch);
    cached_tree_hash_tests!(FoundationHistoricalBatch);
}
