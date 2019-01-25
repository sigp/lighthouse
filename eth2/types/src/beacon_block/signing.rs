use crate::{BeaconBlock, ChainSpec, Hash256, ProposalSignedData};
use ssz::TreeHash;

impl BeaconBlock {
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
        Hash256::from_slice(&proposal.hash_tree_root()[..])
    }
}
