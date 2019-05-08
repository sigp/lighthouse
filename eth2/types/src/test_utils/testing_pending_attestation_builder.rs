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
    /// The `inclusion_slot` will be set to be the earliest possible slot the `Attestation` could
    /// have been included (`slot + MIN_ATTESTATION_INCLUSION_DELAY`).
    ///
    /// * The aggregation and custody bitfields will all be empty, they need to be set with
    /// `Self::add_committee_participation`.
    pub fn new<T: BeaconStateTypes>(
        state: &BeaconState<T>,
        shard: u64,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Self {
        let data_builder = TestingAttestationDataBuilder::new(state, shard, slot, spec);

        let pending_attestation = PendingAttestation {
            aggregation_bitfield: Bitfield::new(),
            data: data_builder.build(),
            custody_bitfield: Bitfield::new(),
            inclusion_slot: slot + spec.min_attestation_inclusion_delay,
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
        let mut custody_bitfield = Bitfield::new();

        for (i, signed) in signers.iter().enumerate() {
            aggregation_bitfield.set(i, *signed);
            custody_bitfield.set(i, false); // Fixed to `false` for phase 0.
        }

        self.pending_attestation.aggregation_bitfield = aggregation_bitfield;
        self.pending_attestation.custody_bitfield = custody_bitfield;
    }

    /// Returns the `PendingAttestation`, consuming the builder.
    pub fn build(self) -> PendingAttestation {
        self.pending_attestation
    }
}
