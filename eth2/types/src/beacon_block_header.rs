use crate::test_utils::TestRandom;
use crate::*;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// A header of a `BeaconBlock`.
///
/// Spec v0.11.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body_root: Hash256,
}

impl SignedRoot for BeaconBlockHeader {}

impl BeaconBlockHeader {
    /// Returns the `tree_hash_root` of the header.
    ///
    /// Spec v0.11.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    /// Given a `body`, consumes `self` and returns a complete `BeaconBlock`.
    ///
    /// Spec v0.11.1
    pub fn into_block<T: EthSpec>(self, body: BeaconBlockBody<T>) -> BeaconBlock<T> {
        BeaconBlock {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body,
        }
    }

    /// Signs `self`, producing a `SignedBeaconBlockHeader`.
    pub fn sign<E: EthSpec>(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedBeaconBlockHeader {
        let epoch = self.slot.epoch(E::slots_per_epoch());
        let domain = spec.get_domain(epoch, Domain::BeaconProposer, fork, genesis_validators_root);
        let message = self.signing_root(domain);
        let signature = Signature::new(message.as_bytes(), secret_key);
        SignedBeaconBlockHeader {
            message: self,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BeaconBlockHeader);
}
