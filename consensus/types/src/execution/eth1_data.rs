use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
#[cfg(feature = "testing")]
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg(feature = "testing")]
use crate::test_utils::TestRandom;
use crate::{core::Hash256, fork::ForkName};

/// Contains data obtained from the Eth1 chain.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "testing", derive(TestRandom))]
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[context_deserialize(ForkName)]
pub struct Eth1Data {
    pub deposit_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_count: u64,
    pub block_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Eth1Data);
}
