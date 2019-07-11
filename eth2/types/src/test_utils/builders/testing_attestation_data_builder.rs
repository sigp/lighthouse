use crate::*;
use tree_hash::TreeHash;

/// Builds an `AttestationData` to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingAttestationDataBuilder {
    data: AttestationData,
}

impl TestingAttestationDataBuilder {
    /// Configures a new `AttestationData` which attests to all of the same parameters as the
    /// state.
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        shard: u64,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Self {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        let is_previous_epoch =
            state.slot.epoch(T::slots_per_epoch()) != slot.epoch(T::slots_per_epoch());

        let source_epoch = if is_previous_epoch {
            state.previous_justified_epoch
        } else {
            state.current_justified_epoch
        };

        let target_epoch = if is_previous_epoch {
            state.previous_epoch()
        } else {
            state.current_epoch()
        };

        let target_root = if is_previous_epoch {
            *state
                .get_block_root(previous_epoch.start_slot(T::slots_per_epoch()))
                .unwrap()
        } else {
            *state
                .get_block_root(current_epoch.start_slot(T::slots_per_epoch()))
                .unwrap()
        };

        let previous_crosslink_root = if is_previous_epoch {
            Hash256::from_slice(
                &state
                    .get_previous_crosslink(shard)
                    .unwrap()
                    .tree_hash_root(),
            )
        } else {
            Hash256::from_slice(&state.get_current_crosslink(shard).unwrap().tree_hash_root())
        };

        let source_root = *state
            .get_block_root(source_epoch.start_slot(T::slots_per_epoch()))
            .unwrap();

        let data = AttestationData {
            // LMD GHOST vote
            beacon_block_root: *state.get_block_root(slot).unwrap(),

            // FFG Vote
            source_epoch,
            source_root,
            target_epoch,
            target_root,

            // Crosslink vote
            shard,
            previous_crosslink_root,
            crosslink_data_root: Hash256::zero(),
        };

        Self { data }
    }

    /// Returns the `AttestationData`, consuming the builder.
    pub fn build(self) -> AttestationData {
        self.data
    }
}
