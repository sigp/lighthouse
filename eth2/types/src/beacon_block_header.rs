use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// A header of a `BeaconBlock`.
///
/// Spec v0.5.0
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub previous_block_root: Hash256,
    pub state_root: Hash256,
    pub block_body_root: Hash256,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlockHeader);
}
