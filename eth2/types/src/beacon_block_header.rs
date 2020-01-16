use crate::test_utils::TestRandom;
use crate::*;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// A header of a `BeaconBlock`.
///
/// Spec v0.9.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body_root: Hash256,
}

impl BeaconBlockHeader {
    /// Returns the `tree_hash_root` of the header.
    ///
    /// Spec v0.9.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    /// Given a `body`, consumes `self` and returns a complete `BeaconBlock`.
    ///
    /// Spec v0.9.1
    pub fn into_block<T: EthSpec>(self, body: BeaconBlockBody<T>) -> BeaconBlock<T> {
        BeaconBlock {
            slot: self.slot,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlockHeader);
}
