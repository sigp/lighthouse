use crate::context_deserialize;
use crate::{Address, ForkName, PublicKeyBytes, SignedRoot, test_utils::TestRandom};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[context_deserialize(ForkName)]
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
