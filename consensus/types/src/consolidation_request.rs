use crate::{test_utils::TestRandom, Address, PublicKeyBytes, SignedRoot};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

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
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: PublicKeyBytes,
    pub target_pubkey: PublicKeyBytes,
}

impl SignedRoot for ConsolidationRequest {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ConsolidationRequest);
}
