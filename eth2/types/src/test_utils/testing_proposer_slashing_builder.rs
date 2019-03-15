use crate::*;
use ssz::SignedRoot;

/// Builds a `ProposerSlashing`.
///
/// This struct should **never be used for production purposes.**
pub struct TestingProposerSlashingBuilder();

impl TestingProposerSlashingBuilder {
    /// Builds a `ProposerSlashing` that is a double vote.
    ///
    /// The `signer` function is used to sign the double-vote and accepts:
    ///
    /// - `validator_index: u64`
    /// - `message: &[u8]`
    /// - `epoch: Epoch`
    /// - `domain: Domain`
    ///
    /// Where domain is a domain "constant" (e.g., `spec.domain_attestation`).
    pub fn double_vote<F>(proposer_index: u64, signer: F, spec: &ChainSpec) -> ProposerSlashing
    where
        F: Fn(u64, &[u8], Epoch, Domain) -> Signature,
    {
        let slot = Slot::new(0);
        let hash_1 = Hash256::from([1; 32]);
        let hash_2 = Hash256::from([2; 32]);

        let mut proposal_1 = BeaconBlockHeader {
            slot,
            previous_block_root: hash_1,
            state_root: hash_1,
            block_body_root: hash_1,
            signature: Signature::empty_signature(),
        };

        let mut proposal_2 = BeaconBlockHeader {
            previous_block_root: hash_2,
            ..proposal_1.clone()
        };

        proposal_1.signature = {
            let message = proposal_1.signed_root();
            let epoch = slot.epoch(spec.slots_per_epoch);
            signer(proposer_index, &message[..], epoch, Domain::Proposal)
        };

        proposal_2.signature = {
            let message = proposal_2.signed_root();
            let epoch = slot.epoch(spec.slots_per_epoch);
            signer(proposer_index, &message[..], epoch, Domain::Proposal)
        };

        ProposerSlashing {
            proposer_index,
            proposal_1,
            proposal_2,
        }
    }
}
