use crate::test_utils::TestingAttestationDataBuilder;
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
        state: &BeaconState<T>,
        committee: &[usize],
        slot: Slot,
        shard: u64,
        spec: &ChainSpec,
    ) -> Self {
        let data_builder = TestingAttestationDataBuilder::new(state, shard, slot, spec);

        let mut aggregation_bits = BitList::with_capacity(committee.len()).unwrap();
        let mut custody_bits = BitList::with_capacity(committee.len()).unwrap();

        for (i, _) in committee.iter().enumerate() {
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
        signing_validators: &[usize],
        secret_keys: &[&SecretKey],
        fork: &Fork,
        spec: &ChainSpec,
        custody_bit: bool,
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

            self.attestation
                .aggregation_bits
                .set(committee_index, true)
                .unwrap();

            if custody_bit {
                self.attestation
                    .custody_bits
                    .set(committee_index, true)
                    .unwrap();
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

            let signature = Signature::new(&message, domain, secret_keys[key_index]);
            self.attestation.signature.add(&signature)
        }

        self
    }

    /// Consume the builder and return the attestation.
    pub fn build(self) -> Attestation<T> {
        self.attestation
    }
}
