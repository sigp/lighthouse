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
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

impl BeaconBlockHeader {
    /// Returns the `hash_tree_root` of the header.
    ///
    /// Spec v0.5.0
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.hash_tree_root()[..])
    }

    /// Given a `body`, consumes `self` and returns a complete `BeaconBlock`.
    ///
    /// Spec v0.5.0
    pub fn into_block(self, body: BeaconBlockBody) -> BeaconBlock {
        BeaconBlock {
            slot: self.slot,
            previous_block_root: self.previous_block_root,
            state_root: self.state_root,
            body,
            signature: self.signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlockHeader);
}
