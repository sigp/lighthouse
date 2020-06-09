use crate::{test_utils::TestRandom, EthSpec, IndexedAttestation};

use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Two conflicting attestations.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Derivative,
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
#[derivative(Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
pub struct AttesterSlashing<T: EthSpec> {
    pub attestation_1: IndexedAttestation<T>,
    pub attestation_2: IndexedAttestation<T>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(AttesterSlashing<MainnetEthSpec>);
}
