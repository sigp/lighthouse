use crate::{test_utils::TestRandom, Address, PublicKeyBytes, SignedRoot};
use serde::{Deserialize, Serialize};
use ssz::Encode;
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

impl ConsolidationRequest {
    pub fn max_size() -> usize {
        Self {
            source_address: Address::repeat_byte(0),
            source_pubkey: PublicKeyBytes::empty(),
            target_pubkey: PublicKeyBytes::empty(),
        }
        .as_ssz_bytes()
        .len()
    }
}

impl SignedRoot for ConsolidationRequest {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ConsolidationRequest);
}
