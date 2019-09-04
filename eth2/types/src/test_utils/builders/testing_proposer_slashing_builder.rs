use crate::*;
use tree_hash::SignedRoot;

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
    pub fn double_vote<T, F>(proposer_index: u64, signer: F) -> ProposerSlashing
    where
        T: EthSpec,
        F: Fn(u64, &[u8], Epoch, Domain) -> Signature,
    {
        let slot = Slot::new(0);
        let hash_1 = Hash256::from([1; 32]);
        let hash_2 = Hash256::from([2; 32]);

        let mut header_1 = BeaconBlockHeader {
            slot,
            parent_root: hash_1,
            state_root: hash_1,
            body_root: hash_1,
            signature: Signature::empty_signature(),
        };

        let mut header_2 = BeaconBlockHeader {
            parent_root: hash_2,
            ..header_1.clone()
        };

        let epoch = slot.epoch(T::slots_per_epoch());

        header_1.signature = {
            let message = header_1.signed_root();
            signer(proposer_index, &message[..], epoch, Domain::BeaconProposer)
        };

        header_2.signature = {
            let message = header_2.signed_root();
            signer(proposer_index, &message[..], epoch, Domain::BeaconProposer)
        };

        ProposerSlashing {
            proposer_index,
            header_1,
            header_2,
        }
    }
}
