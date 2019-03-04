use crate::*;
use ssz::SignedRoot;

/// Builds a `ProposerSlashing`.
pub struct ProposerSlashingBuilder();

impl ProposerSlashingBuilder {
    /// Builds a `ProposerSlashing` that is a double vote.
    ///
    /// The `signer` function is used to sign the double-vote and accepts:
    ///
    /// - `validator_index: u64`
    /// - `message: &[u8]`
    /// - `epoch: Epoch`
    /// - `domain: u64`
    ///
    /// Where domain is a domain "constant" (e.g., `spec.domain_attestation`).
    pub fn double_vote<F>(proposer_index: u64, signer: F, spec: &ChainSpec) -> ProposerSlashing
    where
        F: Fn(u64, &[u8], Epoch, u64) -> Signature,
    {
        let slot = Slot::new(0);
        let shard = 0;

        let mut proposal_1 = Proposal {
            slot,
            shard,
            block_root: Hash256::from(&[1][..]),
            signature: Signature::empty_signature(),
        };

        let mut proposal_2 = Proposal {
            slot,
            shard,
            block_root: Hash256::from(&[2][..]),
            signature: Signature::empty_signature(),
        };

        proposal_1.signature = {
            let message = proposal_1.signed_root();
            let epoch = slot.epoch(spec.slots_per_epoch);
            let domain = spec.domain_proposal;
            signer(proposer_index, &message[..], epoch, domain)
        };

        proposal_2.signature = {
            let message = proposal_2.signed_root();
            let epoch = slot.epoch(spec.slots_per_epoch);
            let domain = spec.domain_proposal;
            signer(proposer_index, &message[..], epoch, domain)
        };

        ProposerSlashing {
            proposer_index,
            proposal_1,
            proposal_2,
        }
    }
}
