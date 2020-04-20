use crate::test_utils::ProposerSlashingTestTask;
use crate::*;

/// Builds a `ProposerSlashing`.
///
/// This struct should **never be used for production purposes.**
pub struct TestingProposerSlashingBuilder;

impl TestingProposerSlashingBuilder {
    /// Builds a `ProposerSlashing` that is a double vote.
    ///
    /// Where domain is a domain "constant" (e.g., `spec.domain_attestation`).
    pub fn double_vote<T>(
        test_task: ProposerSlashingTestTask,
        proposer_index: u64,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> ProposerSlashing
    where
        T: EthSpec,
    {
        let slot = Slot::new(0);
        let hash_1 = Hash256::from([1; 32]);
        let hash_2 = if test_task == ProposerSlashingTestTask::ProposalsIdentical {
            hash_1
        } else {
            Hash256::from([2; 32])
        };

        let mut signed_header_1 = SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot,
                proposer_index,
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

        let mut signed_header_2 = SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                parent_root: hash_2,
                slot: slot_2,
                ..signed_header_1.message.clone()
            },
            signature: Signature::empty_signature(),
        };

        if test_task != ProposerSlashingTestTask::BadProposal1Signature {
            signed_header_1 =
                signed_header_1
                    .message
                    .sign::<T>(secret_key, fork, genesis_validators_root, spec);
        }

        if test_task != ProposerSlashingTestTask::BadProposal2Signature {
            signed_header_2 =
                signed_header_2
                    .message
                    .sign::<T>(secret_key, fork, genesis_validators_root, spec);
        }

        if test_task == ProposerSlashingTestTask::ProposerUnknown {
            signed_header_1.message.proposer_index = 3_141_592;
            signed_header_2.message.proposer_index = 3_141_592;
        }

        ProposerSlashing {
            signed_header_1,
            signed_header_2,
        }
    }
}
