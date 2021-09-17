use crate::test_utils::TestRandom;
use crate::{Checkpoint, Hash256, SignedRoot, Slot};

use crate::slot_data::SlotData;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// The data upon which an attestation is based.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Hash,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    Default,
)]
pub struct AttestationData {
    pub slot: Slot,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,

    // LMD GHOST vote
    pub beacon_block_root: Hash256,

    // FFG Vote
    pub source: Checkpoint,
    pub target: Checkpoint,
}

impl SignedRoot for AttestationData {}

impl SlotData for AttestationData {
    fn get_slot(&self) -> Slot {
        self.slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(AttestationData);
}
