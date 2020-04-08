use crate::{test_utils::TestRandom, BeaconBlock, EthSpec, Hash256, Slot};
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

/// A `BeaconBlock` and a signature from its proposer.
///
/// Spec v0.11.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TestRandom)]
#[serde(bound = "E: EthSpec")]
pub struct SignedBeaconBlock<E: EthSpec> {
    pub message: BeaconBlock<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedBeaconBlock<E> {
    /// Convenience accessor for the block's slot.
    pub fn slot(&self) -> Slot {
        self.message.slot
    }

    /// Convenience accessor for the block's parent root.
    pub fn parent_root(&self) -> Hash256 {
        self.message.parent_root
    }

    /// Convenience accessor for the block's state root.
    pub fn state_root(&self) -> Hash256 {
        self.message.state_root
    }

    /// Returns the `tree_hash_root` of the block.
    ///
    /// Spec v0.11.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.message.tree_hash_root()[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(SignedBeaconBlock<MainnetEthSpec>);
}
