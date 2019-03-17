use super::{AttestationDutyMap, BeaconState, CrosslinkCommittees, Error, ShardCommitteeIndexMap};
use crate::{ChainSpec, Epoch};
use log::trace;
use serde_derive::Serialize;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct EpochCache {
    /// True if this cache has been initialized.
    pub initialized: bool,
    /// The crosslink committees for an epoch.
    pub committees: Vec<CrosslinkCommittees>,
    /// Maps validator index to a slot, shard and committee index for attestation.
    pub attestation_duty_map: AttestationDutyMap,
    /// Maps a shard to an index of `self.committees`.
    pub shard_committee_index_map: ShardCommitteeIndexMap,
}

impl EpochCache {
    pub fn empty() -> EpochCache {
        EpochCache {
            initialized: false,
            committees: vec![],
            attestation_duty_map: AttestationDutyMap::new(),
            shard_committee_index_map: ShardCommitteeIndexMap::new(),
        }
    }

    pub fn initialized(
        state: &BeaconState,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<EpochCache, Error> {
        let mut epoch_committees: Vec<CrosslinkCommittees> =
            Vec::with_capacity(spec.slots_per_epoch as usize);
        let mut attestation_duty_map: AttestationDutyMap = HashMap::new();
        let mut shard_committee_index_map: ShardCommitteeIndexMap = HashMap::new();

        let shuffling =
            state.get_shuffling_for_slot(epoch.start_slot(spec.slots_per_epoch), false, spec)?;

        for (epoch_committeess_index, slot) in epoch.slot_iter(spec.slots_per_epoch).enumerate() {
            let slot_committees = state.calculate_crosslink_committees_at_slot(
                slot,
                false,
                shuffling.clone(),
                spec,
            )?;

            for (slot_committees_index, (committee, shard)) in slot_committees.iter().enumerate() {
                // Empty committees are not permitted.
                if committee.is_empty() {
                    return Err(Error::InsufficientValidators);
                }

                trace!(
                    "shard: {}, epoch_i: {}, slot_i: {}",
                    shard,
                    epoch_committeess_index,
                    slot_committees_index
                );

                shard_committee_index_map
                    .insert(*shard, (epoch_committeess_index, slot_committees_index));

                for (committee_index, validator_index) in committee.iter().enumerate() {
                    attestation_duty_map.insert(
                        *validator_index as u64,
                        (slot, *shard, committee_index as u64),
                    );
                }
            }

            epoch_committees.push(slot_committees)
        }

        Ok(EpochCache {
            initialized: true,
            committees: epoch_committees,
            attestation_duty_map,
            shard_committee_index_map,
        })
    }
}
