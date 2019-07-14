use crate::test_utils::TestingAttestationDataBuilder;
use crate::*;

/// Builds an `AttesterSlashing` to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingPendingAttestationBuilder {
    pending_attestation: PendingAttestation,
}

impl TestingPendingAttestationBuilder {
    /// Create a new valid* `PendingAttestation` for the given parameters.
    ///
    /// The `inclusion_delay` will be set to `MIN_ATTESTATION_INCLUSION_DELAY`.
    ///
    /// * The aggregation and custody bitfields will all be empty, they need to be set with
    /// `Self::add_committee_participation`.
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        shard: u64,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Self {
        let data_builder = TestingAttestationDataBuilder::new(state, shard, slot, spec);

        let relative_epoch =
            RelativeEpoch::from_epoch(state.current_epoch(), slot.epoch(T::slots_per_epoch()))
                .expect("epoch out of bounds");
        let proposer_index = state
            .get_beacon_proposer_index(slot, relative_epoch, spec)
            .unwrap() as u64;

        let pending_attestation = PendingAttestation {
            aggregation_bitfield: Bitfield::new(),
            data: data_builder.build(),
            inclusion_delay: spec.min_attestation_inclusion_delay,
            proposer_index,
        };

        Self {
            pending_attestation,
        }
    }

    /// Sets the committee participation in the `PendingAttestation`.
    ///
    /// The `PendingAttestation` will appear to be signed by each committee member who's value in
    /// `signers` is true.
    pub fn add_committee_participation(&mut self, signers: Vec<bool>) {
        let mut aggregation_bitfield = Bitfield::new();

        for (i, signed) in signers.iter().enumerate() {
            aggregation_bitfield.set(i, *signed);
        }

        self.pending_attestation.aggregation_bitfield = aggregation_bitfield;
    }

    /// Returns the `PendingAttestation`, consuming the builder.
    pub fn build(self) -> PendingAttestation {
        self.pending_attestation
    }
}
