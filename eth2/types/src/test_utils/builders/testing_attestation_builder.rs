use crate::test_utils::{AttestationTestTask, TestingAttestationDataBuilder};
use crate::*;

/// Builds an attestation to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingAttestationBuilder<T: EthSpec> {
    committee: Vec<usize>,
    attestation: Attestation<T>,
}

impl<T: EthSpec> TestingAttestationBuilder<T> {
    /// Create a new attestation builder.
    pub fn new(
        test_task: AttestationTestTask,
        state: &BeaconState<T>,
        committee: &[usize],
        slot: Slot,
        index: u64,
        spec: &ChainSpec,
    ) -> Self {
        let data_builder = TestingAttestationDataBuilder::new(test_task, state, index, slot, spec);

        let mut aggregation_bits_len = committee.len();

        if test_task == AttestationTestTask::BadAggregationBitfieldLen {
            aggregation_bits_len += 1
        }

        let mut aggregation_bits = BitList::with_capacity(aggregation_bits_len).unwrap();

        for i in 0..committee.len() {
            aggregation_bits.set(i, false).unwrap();
        }

        let attestation = Attestation {
            aggregation_bits,
            data: data_builder.build(),
            signature: AggregateSignature::new(),
        };

        Self {
            attestation,
            committee: committee.to_vec(),
        }
    }

    /// Signs the attestation with a subset (or all) committee members.
    ///
    /// `secret_keys` must be supplied in the same order as `signing_validators`. I.e., the first
    /// keypair must be that of the first signing validator.
    pub fn sign(
        &mut self,
        test_task: AttestationTestTask,
        signing_validators: &[usize],
        secret_keys: &[&SecretKey],
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> &mut Self {
        assert_eq!(
            signing_validators.len(),
            secret_keys.len(),
            "Must be a key for each validator"
        );

        for (key_index, validator_index) in signing_validators.iter().enumerate() {
            let committee_index = self
                .committee
                .iter()
                .position(|v| *v == *validator_index)
                .expect("Signing validator not in attestation committee");

            let index = if test_task == AttestationTestTask::BadSignature {
                0
            } else {
                key_index
            };

            self.attestation
                .sign(
                    secret_keys[index],
                    committee_index,
                    fork,
                    genesis_validators_root,
                    spec,
                )
                .expect("can sign attestation");

            self.attestation
                .aggregation_bits
                .set(committee_index, true)
                .unwrap();
        }

        if test_task == AttestationTestTask::BadIndexedAttestationBadSignature {
            // Flip an aggregation bit, to make the aggregate invalid
            // (We also want to avoid making it completely empty)
            self.attestation
                .aggregation_bits
                .set(0, !self.attestation.aggregation_bits.get(0).unwrap())
                .unwrap();
        }

        self
    }

    /// Consume the builder and return the attestation.
    pub fn build(self) -> Attestation<T> {
        self.attestation
    }
}
