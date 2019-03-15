use super::{AttestationDuty, BeaconState, CrosslinkCommittees, Error};
use crate::test_utils::TestRandom;
use crate::{ChainSpec, Epoch};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct EpochCache {
    /// True if this cache has been initialized.
    pub initialized: bool,
    /// The crosslink committees for an epoch.
    pub committees: Vec<CrosslinkCommittees>,
    /// Maps validator index to a slot, shard and committee index for attestation.
    pub attestation_duties: Vec<Option<AttestationDuty>>,
    /// Maps a shard to an index of `self.committees`.
    pub shard_committee_indices: Vec<(usize, usize)>,
}

impl EpochCache {
    /// Return a new, fully initialized cache.
    pub fn initialized(
        state: &BeaconState,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<EpochCache, Error> {
        let mut epoch_committees: Vec<CrosslinkCommittees> =
            Vec::with_capacity(spec.slots_per_epoch as usize);

        let mut attestation_duties = vec![None; state.validator_registry.len()];

        let mut shard_committee_indices = vec![(0, 0); spec.shard_count as usize];

        let mut shuffling =
            state.get_shuffling_for_slot(epoch.start_slot(spec.slots_per_epoch), false, spec)?;

        for (epoch_committees_index, slot) in epoch.slot_iter(spec.slots_per_epoch).enumerate() {
            let mut slot_committees: Vec<(Vec<usize>, u64)> = vec![];

            let shards = state.get_shards_for_slot(slot, false, spec)?;
            for shard in shards {
                let committee = shuffling.remove(0);
                slot_committees.push((committee, shard));
            }

            for (slot_committees_index, (committee, shard)) in slot_committees.iter().enumerate() {
                if committee.is_empty() {
                    return Err(Error::InsufficientValidators);
                }

                // Store the slot and committee index for this shard.
                shard_committee_indices[*shard as usize] =
                    (epoch_committees_index, slot_committees_index);

                // For each validator, store their attestation duties.
                for (committee_index, validator_index) in committee.iter().enumerate() {
                    attestation_duties[*validator_index] =
                        Some((slot, *shard, committee_index as u64))
                }
            }

            epoch_committees.push(slot_committees)
        }

        Ok(EpochCache {
            initialized: true,
            committees: epoch_committees,
            attestation_duties,
            shard_committee_indices,
        })
    }
}

impl<T: RngCore> TestRandom<T> for [EpochCache; 3] {
    /// Test random should generate an empty cache.
    fn random_for_test(rng: &mut T) -> Self {
        [
            EpochCache::default(),
            EpochCache::default(),
            EpochCache::default(),
        ]
    }
}
