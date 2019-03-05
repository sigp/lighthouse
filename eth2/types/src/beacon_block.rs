use crate::test_utils::TestRandom;
use crate::{BeaconBlockBody, ChainSpec, Eth1Data, Hash256, ProposalSignedData, Slot};
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct BeaconBlock {
    pub slot: Slot,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub randao_reveal: Signature,
    pub eth1_data: Eth1Data,
    pub signature: Signature,
    pub body: BeaconBlockBody,
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
                exits: vec![],
            },
        }
    }

    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from(&self.hash_tree_root()[..])
    }

    pub fn proposal_root(&self, spec: &ChainSpec) -> Hash256 {
        let block_without_signature_root = {
            let mut block_without_signature = self.clone();
            block_without_signature.signature = spec.empty_signature.clone();
            block_without_signature.canonical_root()
        };

        let proposal = ProposalSignedData {
            slot: self.slot,
            shard: spec.beacon_chain_shard_number,
            block_root: block_without_signature_root,
        };
        Hash256::from(&proposal.hash_tree_root()[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(BeaconBlock);
}
