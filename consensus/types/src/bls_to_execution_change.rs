use crate::test_utils::TestRandom;
use crate::*;
use bls::PublicKeyBytes;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A deposit to potentially become a beacon chain validator.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, PartialEq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
pub struct BlsToExecutionChange {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub from_bls_pubkey: PublicKeyBytes,
    pub to_execution_address: Address,
}

impl SignedRoot for BlsToExecutionChange {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BlsToExecutionChange);
}
