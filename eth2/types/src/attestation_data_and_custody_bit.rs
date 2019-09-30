use super::AttestationData;
use crate::test_utils::TestRandom;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Used for pairing an attestation with a proof-of-custody.
///
/// Spec v0.8.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct AttestationDataAndCustodyBit {
    pub data: AttestationData,
    pub custody_bit: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    ssz_tests!(AttestationDataAndCustodyBit);
}
