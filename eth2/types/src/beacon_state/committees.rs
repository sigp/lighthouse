use crate::{validator_registry::get_active_validator_indices, BeaconState, ChainSpec};
use log::debug;
use std::ops::Range;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidEpoch(u64, Range<u64>),
    InsufficientNumberOfValidators,
}

macro_rules! ensure {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}

type Result<T> = std::result::Result<T, Error>;

impl BeaconState {
    pub fn current_epoch(&self, spec: &ChainSpec) -> u64 {
        self.slot / spec.epoch_length
    }

    /// Returns the number of committees per slot.
    ///
    /// Note: this is _not_ the committee size.
    pub fn get_committee_count_per_slot(
        &self,
        active_validator_count: usize,
        spec: &ChainSpec,
    ) -> u64 {
        std::cmp::max(
            1,
            std::cmp::min(
                spec.shard_count / spec.epoch_length,
                active_validator_count as u64 / spec.epoch_length / spec.target_committee_size,
            ),
        )
    }

    /// Returns the start slot and end slot of the current epoch containing `self.slot`.
    pub fn get_current_epoch_boundaries(&self, epoch_length: u64) -> Range<u64> {
        let slot_in_epoch = self.slot % epoch_length;
        let start = self.slot - slot_in_epoch;
        let end = self.slot + (epoch_length - slot_in_epoch);
        start..end
    }

    /// Returns the start slot and end slot of the current epoch containing `self.slot`.
    pub fn get_previous_epoch_boundaries(&self, spec: &ChainSpec) -> Range<u64> {
        let current_epoch = self.slot / spec.epoch_length;
        let previous_epoch = current_epoch.saturating_sub(1);
        let start = previous_epoch * spec.epoch_length;
        let end = start + spec.epoch_length;
        start..end
    }

    fn get_previous_epoch_committee_count_per_slot(&self, spec: &ChainSpec) -> u64 {
        let previous_active_validators = get_active_validator_indices(
            &self.validator_registry,
            self.previous_epoch_calculation_slot,
        );
        self.get_committee_count_per_slot(previous_active_validators.len(), spec) as u64
    }

    pub fn get_current_epoch_committee_count_per_slot(&self, spec: &ChainSpec) -> u64 {
        let current_active_validators = get_active_validator_indices(
            &self.validator_registry,
            self.current_epoch_calculation_slot,
        );
        self.get_committee_count_per_slot(current_active_validators.len(), spec)
    }

    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: u64,
        spec: &ChainSpec,
    ) -> Result<Vec<(Vec<usize>, u64)>> {
        /*
        let previous_epoch_range = self.get_current_epoch_boundaries(spec.epoch_length);
        let current_epoch_range = self.get_current_epoch_boundaries(spec.epoch_length);
        if !range_contains(&current_epoch_range, slot) {
            return Err(Error::InvalidEpoch(slot, current_epoch_range));
        }
        */
        let epoch = slot / spec.epoch_length;
        let current_epoch = self.slot / spec.epoch_length;
        let previous_epoch = if current_epoch == spec.genesis_slot {
            current_epoch
        } else {
            current_epoch.saturating_sub(1)
        };
        let next_epoch = current_epoch + 1;

        /*
        debug!(
            "state.slot: {}, slot: {}, current_epoch: {}, previous_epoch: {}, next_epoch: {}",
            self.slot, slot, current_epoch, previous_epoch, next_epoch
        );
        */

        ensure!(
            (previous_epoch <= epoch) & (epoch < next_epoch),
            Error::InvalidEpoch(slot, previous_epoch..current_epoch)
        );

        let offset = slot % spec.epoch_length;

        let (committees_per_slot, shuffling, slot_start_shard) = if epoch < current_epoch {
            let committees_per_slot = self.get_previous_epoch_committee_count_per_slot(spec);
            let shuffling = self.get_shuffling(
                self.previous_epoch_seed,
                self.previous_epoch_calculation_slot,
                spec,
            );
            let slot_start_shard =
                (self.previous_epoch_start_shard + committees_per_slot * offset) % spec.shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        } else {
            let committees_per_slot = self.get_current_epoch_committee_count_per_slot(spec);
            let shuffling = self.get_shuffling(
                self.current_epoch_seed,
                self.current_epoch_calculation_slot,
                spec,
            );
            let slot_start_shard =
                (self.current_epoch_start_shard + committees_per_slot * offset) % spec.shard_count;
            (committees_per_slot, shuffling, slot_start_shard)
        };

        let mut crosslinks_at_slot = vec![];
        for i in 0..committees_per_slot {
            let tuple = (
                shuffling[(committees_per_slot * offset + i) as usize].clone(),
                (slot_start_shard + i) % spec.shard_count,
            );
            crosslinks_at_slot.push(tuple)
        }
        Ok(crosslinks_at_slot)
    }
}

/// Utility function pending this functionality being stabilized on the `Range` type.
fn range_contains<T: PartialOrd>(range: &Range<T>, target: T) -> bool {
    range.start <= target && target < range.end
}
