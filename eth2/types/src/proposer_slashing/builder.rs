use crate::*;
use ssz::TreeHash;

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

        let proposal_data_1 = ProposalSignedData {
            slot,
            shard,
            block_root: Hash256::from_low_u64_le(1),
        };

        let proposal_data_2 = ProposalSignedData {
            slot,
            shard,
            block_root: Hash256::from_low_u64_le(2),
        };

        let proposal_signature_1 = {
            let message = proposal_data_1.hash_tree_root();
            let epoch = slot.epoch(spec.epoch_length);
            let domain = spec.domain_proposal;
            signer(proposer_index, &message[..], epoch, domain)
        };

        let proposal_signature_2 = {
            let message = proposal_data_2.hash_tree_root();
            let epoch = slot.epoch(spec.epoch_length);
            let domain = spec.domain_proposal;
            signer(proposer_index, &message[..], epoch, domain)
        };

        ProposerSlashing {
            proposer_index,
            proposal_data_1,
            proposal_signature_1,
            proposal_data_2,
            proposal_signature_2,
        }
    }
}
