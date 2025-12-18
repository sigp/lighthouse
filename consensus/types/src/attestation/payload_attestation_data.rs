use crate::test_utils::TestRandom;
use crate::{ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    TestRandom, TreeHash, Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Hash,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[context_deserialize(ForkName)]
pub struct PayloadAttestationData {
    pub beacon_block_root: Hash256,
    pub slot: Slot,
    pub payload_present: bool,
    pub blob_data_available: bool,
}

impl SignedRoot for PayloadAttestationData {}

#[cfg(test)]
mod payload_attestation_data_tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestationData);
}
