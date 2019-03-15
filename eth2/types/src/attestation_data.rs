use crate::test_utils::TestRandom;
use crate::{Crosslink, Epoch, Hash256, Slot};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// The data upon which an attestation is based.
///
/// Spec v0.4.0
#[derive(
    Debug,
    Clone,
    PartialEq,
    Default,
    Serialize,
    Deserialize,
    Hash,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct AttestationData {
    pub slot: Slot,
    pub shard: u64,
    pub beacon_block_root: Hash256,
    pub epoch_boundary_root: Hash256,
    pub crosslink_data_root: Hash256,
    pub latest_crosslink: Crosslink,
    pub justified_epoch: Epoch,
    pub justified_block_root: Hash256,
}

impl Eq for AttestationData {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(AttestationData);
}
