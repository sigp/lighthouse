use crate::test_utils::TestRandom;
use crate::{BeaconBlockBody, ChainSpec, Eth1Data, Hash256, Slot};
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// A block of the `BeaconChain`.
///
/// Spec v0.4.0
#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom, SignedRoot)]
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
            signature: spec.empty_signature.clone(),
            body: BeaconBlockBody {
                proposer_slashings: vec![],
                attester_slashings: vec![],
                attestations: vec![],
                deposits: vec![],
                voluntary_exits: vec![],
                transfers: vec![],
            },
        }
    }

    /// Returns the `hash_tree_root` of the block.
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.hash_tree_root()[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlock);
}
