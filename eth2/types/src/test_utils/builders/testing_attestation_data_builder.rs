use crate::test_utils::AttestationTestTask;
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
        test_task: &AttestationTestTask,
        state: &BeaconState<T>,
        mut shard: u64,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Self {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        let is_previous_epoch = slot.epoch(T::slots_per_epoch()) != current_epoch;

        let mut source = if is_previous_epoch {
            state.previous_justified_checkpoint.clone()
        } else {
            state.current_justified_checkpoint.clone()
        };

        let mut target = if is_previous_epoch {
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

        let mut start = parent_crosslink.end_epoch;
        let mut end = std::cmp::min(
            target.epoch,
            parent_crosslink.end_epoch + spec.max_epochs_per_crosslink,
        );
        let mut parent_root = Hash256::from_slice(&parent_crosslink.tree_hash_root());
        let mut data_root = Hash256::zero();
        let beacon_block_root = *state.get_block_root(slot).unwrap();

        match test_task {
            AttestationTestTask::BadParentCrosslinkStartEpoch => start = Epoch::from(10 as u64),
            AttestationTestTask::BadParentCrosslinkEndEpoch => end = Epoch::from(0 as u64),
            AttestationTestTask::BadParentCrosslinkHash => parent_root = Hash256::zero(),
            AttestationTestTask::NoCommiteeForShard => shard += 2,
            AttestationTestTask::BadShard => shard = T::ShardCount::to_u64(),
            AttestationTestTask::IncludedTooEarly => shard += 1,
            AttestationTestTask::IncludedTooLate => {
                target = Checkpoint {
                    epoch: Epoch::from(3 as u64),
                    root: Hash256::zero(),
                }
            }
            AttestationTestTask::BadTargetEpoch => {
                target = Checkpoint {
                    epoch: Epoch::from(5 as u64),
                    root: Hash256::zero(),
                }
            }
            AttestationTestTask::WrongJustifiedCheckpoint => {
                source = Checkpoint {
                    epoch: Epoch::from(0 as u64),
                    root: Hash256::zero(),
                }
            }
            AttestationTestTask::BadTargetTooLow => {
                target = Checkpoint {
                    epoch: Epoch::from(0 as u64),
                    root: Hash256::zero(),
                }
            }
            AttestationTestTask::BadTargetTooHigh => {
                target = Checkpoint {
                    epoch: Epoch::from(10 as u64),
                    root: Hash256::zero(),
                }
            }
            AttestationTestTask::BadParentCrosslinkDataRoot => data_root = parent_root,
            _ => (),
        }
        let crosslink = Crosslink {
            shard,
            parent_root,
            start_epoch: start,
            end_epoch: end,
            data_root,
        };

        let data = AttestationData {
            // LMD GHOST vote
            beacon_block_root,

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
