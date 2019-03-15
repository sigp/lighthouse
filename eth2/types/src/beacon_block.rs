use crate::test_utils::TestRandom;
use crate::{BeaconBlockBody, ChainSpec, Eth1Data, Hash256, Proposal, Slot};
use bls::Signature;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::{SignedRoot, TreeHash};
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// A block of the `BeaconChain`.
///
/// Spec v0.4.0
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
pub struct BeaconBlock {
    pub slot: Slot,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub body: BeaconBlockBody,
    pub signature: Signature,
}

impl BeaconBlock {
    /// Produce the first block of the Beacon Chain.
    ///
    /// Spec v0.4.0
    pub fn genesis(state_root: Hash256, spec: &ChainSpec) -> BeaconBlock {
        BeaconBlock {
            slot: spec.genesis_slot,
            parent_root: spec.zero_hash,
            state_root,
            randao_reveal: spec.empty_signature.clone(),
            eth1_data: Eth1Data {
                deposit_root: spec.zero_hash,
                block_hash: spec.zero_hash,
            },
            body: BeaconBlockBody {
                proposer_slashings: vec![],
                attester_slashings: vec![],
                attestations: vec![],
                deposits: vec![],
                voluntary_exits: vec![],
                transfers: vec![],
            },
            signature: spec.empty_signature.clone(),
        }
    }

    /// Returns the `hash_tree_root` of the block.
    ///
    /// Spec v0.4.0
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.hash_tree_root()[..])
    }

    /// Returns an unsigned proposal for block.
    ///
    /// Spec v0.4.0
    pub fn proposal(&self, spec: &ChainSpec) -> Proposal {
        Proposal {
            slot: self.slot,
            shard: spec.beacon_chain_shard_number,
            block_root: Hash256::from_slice(&self.signed_root()),
            signature: spec.empty_signature.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlock);
}
