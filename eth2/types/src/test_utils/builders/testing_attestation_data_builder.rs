use crate::test_utils::AttestationTestTask;
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
    pub fn new<T: EthSpec>(
        test_task: AttestationTestTask,
        state: &BeaconState<T>,
        index: u64,
        mut slot: Slot,
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

        let beacon_block_root = *state.get_block_root(slot).unwrap();

        match test_task {
            // FIXME: re-enable the shard-like tests
            // AttestationTestTask::NoCommiteeForShard => index += 2,
            // AttestationTestTask::BadShard => index = T::ShardCount::to_u64(),
            AttestationTestTask::IncludedTooEarly => {
                slot = state.slot - spec.min_attestation_inclusion_delay + 1
            }
            AttestationTestTask::IncludedTooLate => slot -= T::SlotsPerEpoch::to_u64(),
            AttestationTestTask::TargetEpochSlotMismatch => {
                target = Checkpoint {
                    epoch: current_epoch + 1,
                    root: Hash256::zero(),
                };
                assert_ne!(target.epoch, slot.epoch(T::slots_per_epoch()));
            }
            AttestationTestTask::WrongJustifiedCheckpoint => {
                source = Checkpoint {
                    epoch: Epoch::from(0 as u64),
                    root: Hash256::zero(),
                }
            }
            _ => (),
        }

        let data = AttestationData {
            slot,
            index,

            // LMD GHOST vote
            beacon_block_root,

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
