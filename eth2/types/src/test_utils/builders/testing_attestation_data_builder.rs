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
    pub fn new<T: EthSpec>(state: &BeaconState<T>, index: u64, slot: Slot) -> Self {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        let is_previous_epoch = slot.epoch(T::slots_per_epoch()) != current_epoch;

        let source = if is_previous_epoch {
            state.previous_justified_checkpoint.clone()
        } else {
            state.current_justified_checkpoint.clone()
        };

        let target = if is_previous_epoch {
            Checkpoint {
                epoch: previous_epoch,
                root: *state
                    .get_block_root(previous_epoch.start_slot(T::slots_per_epoch()))
                    .unwrap(),
            }
        } else {
            Checkpoint {
                epoch: current_epoch,
                root: *state
                    .get_block_root(current_epoch.start_slot(T::slots_per_epoch()))
                    .unwrap(),
            }
        };

        let data = AttestationData {
            slot,
            index,

            // LMD GHOST vote
            beacon_block_root: *state.get_block_root(slot).unwrap(),

            // FFG Vote
            source,
            target,
        };

        Self { data }
    }

    /// Returns the `AttestationData`, consuming the builder.
    pub fn build(self) -> AttestationData {
        self.data
    }
}
