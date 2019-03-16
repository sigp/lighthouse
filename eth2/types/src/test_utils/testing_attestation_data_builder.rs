use crate::*;

/// Builds an `AttestationData` to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingAttestationDataBuilder {
    data: AttestationData,
}

impl TestingAttestationDataBuilder {
    /// Configures a new `AttestationData` which attests to all of the same parameters as the
    /// state.
    pub fn new(state: &BeaconState, shard: u64, slot: Slot, spec: &ChainSpec) -> Self {
        let current_epoch = state.current_epoch(spec);
        let previous_epoch = state.previous_epoch(spec);

        let is_previous_epoch =
            state.slot.epoch(spec.slots_per_epoch) != slot.epoch(spec.slots_per_epoch);

        let source_epoch = if is_previous_epoch {
            state.previous_justified_epoch
        } else {
            state.current_justified_epoch
        };

        let target_root = if is_previous_epoch {
            *state
                .get_block_root(previous_epoch.start_slot(spec.slots_per_epoch), spec)
                .unwrap()
        } else {
            *state
                .get_block_root(current_epoch.start_slot(spec.slots_per_epoch), spec)
                .unwrap()
        };

        let source_root = *state
            .get_block_root(source_epoch.start_slot(spec.slots_per_epoch), spec)
            .unwrap();

        let data = AttestationData {
            // LMD GHOST vote
            slot,
            beacon_block_root: *state.get_block_root(slot, spec).unwrap(),

            // FFG Vote
            source_epoch,
            source_root,
            target_root,

            // Crosslink vote
            shard,
            previous_crosslink: Crosslink {
                epoch: slot.epoch(spec.slots_per_epoch),
                crosslink_data_root: spec.zero_hash,
            },
            crosslink_data_root: spec.zero_hash,
        };

        Self { data }
    }

    /// Returns the `AttestationData`, consuming the builder.
    pub fn build(self) -> AttestationData {
        self.data
    }
}
