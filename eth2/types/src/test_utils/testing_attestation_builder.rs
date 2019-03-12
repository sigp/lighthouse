use crate::*;
use ssz::TreeHash;

/// Builds an attestation to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingAttestationBuilder {
    committee: Vec<usize>,
    attestation: Attestation,
}

impl TestingAttestationBuilder {
    /// Create a new attestation builder.
    pub fn new(
        state: &BeaconState,
        committee: &[usize],
        slot: Slot,
        shard: u64,
        spec: &ChainSpec,
    ) -> Self {
        let current_epoch = state.current_epoch(spec);
        let previous_epoch = state.previous_epoch(spec);

        let is_previous_epoch =
            state.slot.epoch(spec.slots_per_epoch) != slot.epoch(spec.slots_per_epoch);

        let justified_epoch = if is_previous_epoch {
            state.previous_justified_epoch
        } else {
            state.justified_epoch
        };

        let epoch_boundary_root = if is_previous_epoch {
            *state
                .get_block_root(previous_epoch.start_slot(spec.slots_per_epoch), spec)
                .unwrap()
        } else {
            *state
                .get_block_root(current_epoch.start_slot(spec.slots_per_epoch), spec)
                .unwrap()
        };

        let justified_block_root = *state
            .get_block_root(justified_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap();

        let mut aggregation_bitfield = Bitfield::new();
        let mut custody_bitfield = Bitfield::new();

        for (i, _) in committee.iter().enumerate() {
            custody_bitfield.set(i, false);
            aggregation_bitfield.set(i, false);
        }

        let attestation = Attestation {
            aggregation_bitfield,
            data: AttestationData {
                slot,
                shard,
                beacon_block_root: *state.get_block_root(slot, spec).unwrap(),
                epoch_boundary_root,
                crosslink_data_root: Hash256::zero(),
                latest_crosslink: state.latest_crosslinks[shard as usize].clone(),
                justified_epoch,
                justified_block_root,
            },
            custody_bitfield,
            aggregate_signature: AggregateSignature::new(),
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
    ) {
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
                .aggregation_bitfield
                .set(committee_index, true);

            let message = AttestationDataAndCustodyBit {
                data: self.attestation.data.clone(),
                custody_bit: false,
            }
            .hash_tree_root();

            let domain = spec.get_domain(
                self.attestation.data.slot.epoch(spec.slots_per_epoch),
                Domain::Attestation,
                fork,
            );

            let signature = Signature::new(&message, domain, secret_keys[key_index]);
            self.attestation.aggregate_signature.add(&signature)
        }
    }

    /// Consume the builder and return the attestation.
    pub fn build(self) -> Attestation {
        self.attestation
    }
}
