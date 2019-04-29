use crate::{test_utils::TestRandom, IndexedAttestation};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Two conflicting attestations.
///
/// Spec v0.6.0
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
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(AttesterSlashing);
    cached_tree_hash_tests!(AttesterSlashing);
}
