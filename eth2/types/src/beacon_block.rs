use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, SignedRoot, TreeHash};

/// A block of the `BeaconChain`.
///
/// Spec v0.6.1
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
pub struct BeaconBlock {
    pub slot: Slot,
    pub previous_block_root: Hash256,
    pub state_root: Hash256,
    pub body: BeaconBlockBody,
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

impl BeaconBlock {
    /// Returns an empty block to be used during genesis.
    ///
    /// Spec v0.6.1
    pub fn empty(spec: &ChainSpec) -> BeaconBlock {
        BeaconBlock {
            slot: spec.genesis_slot,
            previous_block_root: spec.zero_hash,
            state_root: spec.zero_hash,
            body: BeaconBlockBody {
                randao_reveal: Signature::empty_signature(),
                eth1_data: Eth1Data {
                    deposit_root: spec.zero_hash,
                    block_hash: spec.zero_hash,
                    deposit_count: 0,
                },
                graffiti: [0; 32],
                proposer_slashings: vec![],
                attester_slashings: vec![],
                attestations: vec![],
                deposits: vec![],
                voluntary_exits: vec![],
                transfers: vec![],
            },
            signature: Signature::empty_signature(),
        }
    }

    /// Returns the `tree_hash_root | update` of the block.
    ///
    /// Spec v0.6.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    /// Returns a full `BeaconBlockHeader` of this block.
    ///
    /// Note: This method is used instead of an `Into` impl to avoid a `Clone` of an entire block
    /// when you want to have the block _and_ the header.
    ///
    /// Note: performs a full tree-hash of `self.body`.
    ///
    /// Spec v0.6.1
    pub fn block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            previous_block_root: self.previous_block_root,
            state_root: self.state_root,
            block_body_root: Hash256::from_slice(&self.body.tree_hash_root()[..]),
            signature: self.signature.clone(),
        }
    }

    /// Returns a "temporary" header, where the `state_root` is `spec.zero_hash`.
    ///
    /// Spec v0.6.1
    pub fn temporary_block_header(&self, spec: &ChainSpec) -> BeaconBlockHeader {
        BeaconBlockHeader {
            state_root: spec.zero_hash,
            signature: Signature::empty_signature(),
            ..self.block_header()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlock);
    cached_tree_hash_tests!(BeaconBlock);
}
