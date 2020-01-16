use crate::test_utils::ProposerSlashingTestTask;
use crate::*;

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
    pub fn double_vote<T, F>(
        test_task: ProposerSlashingTestTask,
        mut proposer_index: u64,
        _signer: F,
    ) -> ProposerSlashing
    where
        T: EthSpec,
        F: Fn(u64, &[u8], Epoch, Domain) -> Signature,
    {
        let slot = Slot::new(0);
        let hash_1 = Hash256::from([1; 32]);
        let hash_2 = if test_task == ProposerSlashingTestTask::ProposalsIdentical {
            hash_1.clone()
        } else {
            Hash256::from([2; 32])
        };

        let signed_header_1 = SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot,
                parent_root: hash_1,
                state_root: hash_1,
                body_root: hash_1,
            },
            signature: Signature::empty_signature(),
        };

        let slot_2 = if test_task == ProposerSlashingTestTask::ProposalEpochMismatch {
            Slot::new(128)
        } else {
            Slot::new(0)
        };

        let signed_header_2 = SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                parent_root: hash_2,
                slot: slot_2,
                ..signed_header_1.message.clone()
            },
            signature: Signature::empty_signature(),
        };

        /* FIXME(sproul)
        let _epoch = slot.epoch(T::slots_per_epoch());
        if test_task != ProposerSlashingTestTask::BadProposal1Signature {
            signed_header_1.signature = {
                let message = signed_header_1.signed_root();
                signer(proposer_index, &message[..], epoch, Domain::BeaconProposer)
            };
        }

        if test_task != ProposerSlashingTestTask::BadProposal2Signature {
            signed_header_2.signature = {
                let message = signed_header_2.signed_root();
                signer(proposer_index, &message[..], epoch, Domain::BeaconProposer)
            };
        }
        */

        if test_task == ProposerSlashingTestTask::ProposerUnknown {
            proposer_index = 3_141_592;
        }

        ProposerSlashing {
            proposer_index,
            signed_header_1,
            signed_header_2,
        }
    }
}
