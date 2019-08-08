use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::{SignedRoot, TreeHash};
use tree_hash_derive::{SignedRoot, TreeHash};

/// A block of the `BeaconChain`.
///
/// Spec v0.8.0
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
#[serde(bound = "T: EthSpec")]
pub struct BeaconBlock<T: EthSpec> {
    pub slot: Slot,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body: BeaconBlockBody<T>,
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

impl<T: EthSpec> BeaconBlock<T> {
    /// Returns an empty block to be used during genesis.
    ///
    /// Spec v0.8.1
    pub fn empty(spec: &ChainSpec) -> Self {
        BeaconBlock {
            slot: spec.genesis_slot,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBody {
                randao_reveal: Signature::empty_signature(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: [0; 32],
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                transfers: VariableList::empty(),
            },
            signature: Signature::empty_signature(),
        }
    }

    /// Returns the epoch corresponding to `self.slot`.
    pub fn epoch(&self) -> Epoch {
        self.slot.epoch(T::slots_per_epoch())
    }

    /// Returns the `signed_root` of the block.
    ///
    /// Spec v0.8.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.signed_root()[..])
    }

    /// Returns a full `BeaconBlockHeader` of this block.
    ///
    /// Note: This method is used instead of an `Into` impl to avoid a `Clone` of an entire block
    /// when you want to have the block _and_ the header.
    ///
    /// Note: performs a full tree-hash of `self.body`.
    ///
    /// Spec v0.8.1
    pub fn block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: Hash256::from_slice(&self.body.tree_hash_root()[..]),
            signature: self.signature.clone(),
        }
    }

    /// Returns a "temporary" header, where the `state_root` is `Hash256::zero()`.
    ///
    /// Spec v0.8.0
    pub fn temporary_block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            state_root: Hash256::zero(),
            signature: Signature::empty_signature(),
            ..self.block_header()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlock<MainnetEthSpec>);
}
