use crate::test_utils::AttesterSlashingTestTask;
use crate::*;

/// Builds an `AttesterSlashing`.
///
/// This struct should **never be used for production purposes.**
pub struct TestingAttesterSlashingBuilder();

impl TestingAttesterSlashingBuilder {
    /// Builds an `AttesterSlashing` that is a double vote.
    ///
    /// The `signer` function is used to sign the double-vote and accepts:
    ///
    /// - `validator_index: u64`
    /// - `message: &[u8]`
    pub fn double_vote<F, T: EthSpec>(
        test_task: AttesterSlashingTestTask,
        validator_indices: &[u64],
        signer: F,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> AttesterSlashing<T>
    where
        F: Fn(u64, &[u8]) -> Signature,
    {
        TestingAttesterSlashingBuilder::double_vote_with_additional_indices(
            test_task,
            validator_indices,
            None,
            signer,
            fork,
            genesis_validators_root,
            spec,
        )
    }

    pub fn double_vote_with_additional_indices<F, T: EthSpec>(
        test_task: AttesterSlashingTestTask,
        validator_indices: &[u64],
        additional_validator_indices: Option<&[u64]>,
        signer: F,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> AttesterSlashing<T>
    where
        F: Fn(u64, &[u8]) -> Signature,
    {
        let slot = Slot::new(1);
        let index = 0;
        let epoch_1 = Epoch::new(1);
        let hash_1 = Hash256::from_low_u64_le(1);
        let hash_2 = Hash256::from_low_u64_le(2);
        let checkpoint_1 = Checkpoint {
            epoch: epoch_1,
            root: hash_1,
        };
        let checkpoint_2 = Checkpoint {
            epoch: epoch_1,
            root: hash_2,
        };

        let data_1 = AttestationData {
            slot,
            index,
            beacon_block_root: hash_1,
            source: checkpoint_1,
            target: checkpoint_1,
        };

        let data_2 = if test_task == AttesterSlashingTestTask::NotSlashable {
            data_1.clone()
        } else {
            AttestationData {
                target: checkpoint_2,
                ..data_1
            }
        };

        let mut attestation_1 = IndexedAttestation {
            attesting_indices: if test_task == AttesterSlashingTestTask::IndexedAttestation1Invalid
            {
                // Trigger bad validator indices ordering error.
                vec![1, 0].into()
            } else {
                validator_indices.to_vec().into()
            },
            data: data_1,
            signature: AggregateSignature::empty(),
        };

        let mut attestation_2 = IndexedAttestation {
            attesting_indices: if test_task == AttesterSlashingTestTask::IndexedAttestation2Invalid
            {
                // Trigger bad validator indices ordering error.
                vec![1, 0].into()
            } else {
                match additional_validator_indices {
                    Some(x) => x.to_vec().into(),
                    None => validator_indices.to_vec().into(),
                }
            },
            data: data_2,
            signature: AggregateSignature::empty(),
        };

        let add_signatures = |attestation: &mut IndexedAttestation<T>, indices_to_sign: &[u64]| {
            let domain = spec.get_domain(
                attestation.data.target.epoch,
                Domain::BeaconAttester,
                fork,
                genesis_validators_root,
            );
            let message = attestation.data.signing_root(domain);

            for validator_index in indices_to_sign {
                let signature = signer(*validator_index, message.as_bytes());
                attestation.signature.add_assign(&signature);
            }
        };

        add_signatures(&mut attestation_1, validator_indices);
        add_signatures(
            &mut attestation_2,
            additional_validator_indices.unwrap_or(validator_indices),
        );

        AttesterSlashing {
            attestation_1,
            attestation_2,
        }
    }
}
