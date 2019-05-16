use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::{SignedRoot, TreeHash};
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

/// A header of a `BeaconBlock`.
///
/// Spec v0.5.1
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
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
    /// Returns the `tree_hash_root` of the header.
    ///
    /// Spec v0.5.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.signed_root()[..])
    }

    /// Given a `body`, consumes `self` and returns a complete `BeaconBlock`.
    ///
    /// Spec v0.5.1
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
    cached_tree_hash_tests!(BeaconBlockHeader);
}
