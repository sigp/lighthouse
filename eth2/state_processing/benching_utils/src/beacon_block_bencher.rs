use ssz::{SignedRoot, TreeHash};
use types::*;

pub struct BeaconBlockBencher {
    block: BeaconBlock,
}

impl BeaconBlockBencher {
    pub fn new(spec: &ChainSpec) -> Self {
        Self {
            block: BeaconBlock::genesis(spec.zero_hash, spec),
        }
    }

    pub fn set_slot(&mut self, slot: Slot) {
        self.block.slot = slot;
    }

    /// Signs the block.
    pub fn sign(&mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let proposal = self.block.proposal(spec);
        let message = proposal.signed_root();
        let epoch = self.block.slot.epoch(spec.slots_per_epoch);
        let domain = spec.get_domain(epoch, Domain::Proposal, fork);
        self.block.signature = Signature::new(&message, domain, sk);
    }

    /// Sets the randao to be a signature across the blocks epoch.
    pub fn set_randao_reveal(&mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let epoch = self.block.slot.epoch(spec.slots_per_epoch);
        let message = epoch.hash_tree_root();
        let domain = spec.get_domain(epoch, Domain::Randao, fork);
        self.block.randao_reveal = Signature::new(&message, domain, sk);
    }

    /// Signs and returns the block, consuming the builder.
    pub fn build(mut self, sk: &SecretKey, fork: &Fork, spec: &ChainSpec) -> BeaconBlock {
        self.sign(sk, fork, spec);
        self.block
    }

    /// Returns the block, consuming the builder.
    pub fn build_without_signing(self) -> BeaconBlock {
        self.block
    }
}
