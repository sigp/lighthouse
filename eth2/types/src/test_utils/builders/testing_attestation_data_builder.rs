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

        let parent_crosslink = if is_previous_epoch {
            state.get_previous_crosslink(shard).unwrap()
        } else {
            state.get_current_crosslink(shard).unwrap()
        };

        let crosslink = Crosslink {
            shard,
            parent_root: Hash256::from_slice(&parent_crosslink.tree_hash_root()),
            start_epoch: parent_crosslink.end_epoch,
            end_epoch: std::cmp::min(
                target.epoch,
                parent_crosslink.end_epoch + spec.max_epochs_per_crosslink,
            ),
            data_root: Hash256::zero(),
        };

        let data = AttestationData {
            // LMD GHOST vote
            beacon_block_root: *state.get_block_root(slot).unwrap(),

            // FFG Vote
            source,
            target,

            // Crosslink vote
            crosslink,
        };

        Self { data }
    }

    /// Returns the `AttestationData`, consuming the builder.
    pub fn build(self) -> AttestationData {
        self.data
    }
}
