use super::AttestationData;
use crate::test_utils::TestRandom;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// Used for pairing an attestation with a proof-of-custody.
///
/// Spec v0.6.1
#[derive(
    Debug,
    Clone,
    PartialEq,
    Default,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
)]
pub struct AttestationDataAndCustodyBit {
    pub data: AttestationData,
    pub custody_bit: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    ssz_tests!(AttestationDataAndCustodyBit);
    cached_tree_hash_tests!(AttestationDataAndCustodyBit);
}
