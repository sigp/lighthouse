use crate::test_utils::TestRandom;
use crate::*;

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Historical block and state roots.
///
/// Spec v0.12.1
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[context_deserialize(ForkName)]
pub struct HistoricalBatch<E: EthSpec> {
    #[test_random(default)]
    pub block_roots: Vector<Hash256, E::SlotsPerHistoricalRoot>,
    #[test_random(default)]
    pub state_roots: Vector<Hash256, E::SlotsPerHistoricalRoot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    pub type FoundationHistoricalBatch = HistoricalBatch<MainnetEthSpec>;

    ssz_and_tree_hash_tests!(FoundationHistoricalBatch);
}
