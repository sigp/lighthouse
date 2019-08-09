use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::{SignedRoot, TreeHash};
use tree_hash_derive::{SignedRoot, TreeHash};

/// A header of a `BeaconBlock`.
///
/// Spec v0.8.1
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
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body_root: Hash256,
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

impl BeaconBlockHeader {
    /// Returns the `tree_hash_root` of the header.
    ///
    /// Spec v0.8.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.signed_root()[..])
    }

    /// Given a `body`, consumes `self` and returns a complete `BeaconBlock`.
    ///
    /// Spec v0.8.0
    pub fn into_block<T: EthSpec>(self, body: BeaconBlockBody<T>) -> BeaconBlock<T> {
        BeaconBlock {
            slot: self.slot,
            parent_root: self.parent_root,
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
