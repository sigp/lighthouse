use crate::{test_utils::TestRandom, EthSpec, IndexedAttestation};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Two conflicting attestations.
///
/// Spec v0.8.0
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
)]
#[serde(bound = "T: EthSpec")]
pub struct AttesterSlashing<T: EthSpec> {
    pub attestation_1: IndexedAttestation<T>,
    pub attestation_2: IndexedAttestation<T>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_tests!(AttesterSlashing<MainnetEthSpec>);
    cached_tree_hash_tests!(AttesterSlashing<MainnetEthSpec>);
}
