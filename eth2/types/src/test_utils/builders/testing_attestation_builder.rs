use crate::test_utils::{AttestationTestTask, TestingAttestationDataBuilder};
use crate::*;
use tree_hash::TreeHash;

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
        test_task: &AttestationTestTask,
        state: &BeaconState<T>,
        committee: &[usize],
        slot: Slot,
        shard: u64,
        spec: &ChainSpec,
    ) -> Self {
        let data_builder = TestingAttestationDataBuilder::new(test_task, state, shard, slot, spec);

        let mut aggregation_bits_len = committee.len();
        let mut custody_bits_len = committee.len();

        match test_task {
            AttestationTestTask::BadAggregationBitfieldLen => aggregation_bits_len += 1,
            AttestationTestTask::BadCustodyBitfieldLen => custody_bits_len += 1,
            _ => (),
        }
        let mut aggregation_bits = BitList::with_capacity(aggregation_bits_len).unwrap();
        let mut custody_bits = BitList::with_capacity(custody_bits_len).unwrap();

        for i in 0..committee.len() {
            custody_bits.set(i, false).unwrap();
            aggregation_bits.set(i, false).unwrap();
        }

        let attestation = Attestation {
            aggregation_bits,
            data: data_builder.build(),
            custody_bits,
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
        test_task: &AttestationTestTask,
        signing_validators: &[usize],
        secret_keys: &[&SecretKey],
        fork: &Fork,
        spec: &ChainSpec,
        mut custody_bit: bool,
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

            match test_task {
                AttestationTestTask::BadIndexedAttestationBadSignature => (),
                AttestationTestTask::CustodyBitfieldNotSubset => custody_bit = true,
                _ => {
                    self.attestation
                        .aggregation_bits
                        .set(committee_index, true)
                        .unwrap();
                }
            }
            match (custody_bit, test_task) {
                (true, _) | (_, AttestationTestTask::CustodyBitfieldHasSetBits) => {
                    self.attestation
                        .custody_bits
                        .set(committee_index, true)
                        .unwrap();
                }
                (false, _) => (),
            }

            let message = AttestationDataAndCustodyBit {
                data: self.attestation.data.clone(),
                custody_bit,
            }
            .tree_hash_root();

            let domain = spec.get_domain(
                self.attestation.data.target.epoch,
                Domain::Attestation,
                fork,
            );

            let index = if *test_task == AttestationTestTask::BadSignature {
                0
            } else {
                key_index
            };
            let signature = Signature::new(&message, domain, secret_keys[index]);
            self.attestation.signature.add(&signature)
        }

        self
    }

    /// Consume the builder and return the attestation.
    pub fn build(self) -> Attestation<T> {
        self.attestation
    }
}
