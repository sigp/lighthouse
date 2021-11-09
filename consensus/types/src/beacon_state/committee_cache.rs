#![allow(clippy::integer_arithmetic)]

use super::BeaconState;
use crate::*;
use core::num::NonZeroUsize;
use safe_arith::SafeArith;
use serde_derive::{Deserialize, Serialize};
use ssz::{four_byte_option_impl, Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::ops::Range;
use swap_or_not_shuffle::shuffle_list;

mod tests;

// Define "legacy" implementations of `Option<Epoch>`, `Option<NonZeroUsize>` which use four bytes
// for encoding the union selector.
four_byte_option_impl!(four_byte_option_epoch, Epoch);
four_byte_option_impl!(four_byte_option_non_zero_usize, NonZeroUsize);

/// Computes and stores the shuffling for an epoch. Provides various getters to allow callers to
/// read the committees for the given epoch.
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct CommitteeCache {
    #[ssz(with = "four_byte_option_epoch")]
    initialized_epoch: Option<Epoch>,
    shuffling: Vec<usize>,
    shuffling_positions: Vec<NonZeroUsizeOption>,
    committees_per_slot: u64,
    slots_per_epoch: u64,
}

impl CommitteeCache {
    /// Return a new, fully initialized cache.
    ///
    /// Spec v0.12.1
    pub fn initialized<T: EthSpec>(
        state: &BeaconState<T>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<CommitteeCache, Error> {
        RelativeEpoch::from_epoch(state.current_epoch(), epoch)
            .map_err(|_| Error::EpochOutOfBounds)?;

        // May cause divide-by-zero errors.
        if T::slots_per_epoch() == 0 {
            return Err(Error::ZeroSlotsPerEpoch);
        }

        let active_validator_indices = get_active_validator_indices(state.validators(), epoch);

        if active_validator_indices.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let committees_per_slot =
            T::get_committee_count_per_slot(active_validator_indices.len(), spec)? as u64;

        let seed = state.get_seed(epoch, Domain::BeaconAttester, spec)?;

        let shuffling = shuffle_list(
            active_validator_indices,
            spec.shuffle_round_count,
            &seed[..],
            false,
        )
        .ok_or(Error::UnableToShuffle)?;

        // The use of `NonZeroUsize` reduces the maximum number of possible validators by one.
        if state.validators().len() == usize::max_value() {
            return Err(Error::TooManyValidators);
        }

        let mut shuffling_positions = vec![<_>::default(); state.validators().len()];
        for (i, &v) in shuffling.iter().enumerate() {
            *shuffling_positions
                .get_mut(v)
                .ok_or(Error::ShuffleIndexOutOfBounds(v))? = NonZeroUsize::new(i + 1).into();
        }

        Ok(CommitteeCache {
            initialized_epoch: Some(epoch),
            shuffling,
            shuffling_positions,
            committees_per_slot,
            slots_per_epoch: T::slots_per_epoch(),
        })
    }

    /// Returns `true` if the cache has been initialized at the supplied `epoch`.
    ///
    /// An non-initialized cache does not provide any useful information.
    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    /// Returns the **shuffled** list of active validator indices for the initialized epoch.
    ///
    /// These indices are not in ascending order.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn active_validator_indices(&self) -> &[usize] {
        &self.shuffling
    }

    /// Returns the shuffled list of active validator indices for the initialized epoch.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn shuffling(&self) -> &[usize] {
        &self.shuffling
    }

    /// Get the Beacon committee for the given `slot` and `index`.
    ///
    /// Return `None` if the cache is uninitialized, or the `slot` or `index` is out of range.
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Option<BeaconCommittee> {
        if self.initialized_epoch.is_none()
            || !self.is_initialized_at(slot.epoch(self.slots_per_epoch))
            || index >= self.committees_per_slot
        {
            return None;
        }

        let committee_index = compute_committee_index_in_epoch(
            slot,
            self.slots_per_epoch as usize,
            self.committees_per_slot as usize,
            index as usize,
        );
        let committee = self.compute_committee(committee_index as usize)?;

        Some(BeaconCommittee {
            slot,
            index,
            committee,
        })
    }

    /// Get all the Beacon committees at a given `slot`.
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<BeaconCommittee>, Error> {
        if self.initialized_epoch.is_none() {
            return Err(Error::CommitteeCacheUninitialized(None));
        }

        (0..self.committees_per_slot())
            .map(|index| {
                self.get_beacon_committee(slot, index)
                    .ok_or(Error::NoCommittee { slot, index })
            })
            .collect()
    }

    /// Returns all committees for `self.initialized_epoch`.
    pub fn get_all_beacon_committees(&self) -> Result<Vec<BeaconCommittee>, Error> {
        let initialized_epoch = self
            .initialized_epoch
            .ok_or(Error::CommitteeCacheUninitialized(None))?;

        initialized_epoch.slot_iter(self.slots_per_epoch).try_fold(
            Vec::with_capacity(self.slots_per_epoch as usize),
            |mut vec, slot| {
                vec.append(&mut self.get_beacon_committees_at_slot(slot)?);
                Ok(vec)
            },
        )
    }

    /// Returns the `AttestationDuty` for the given `validator_index`.
    ///
    /// Returns `None` if the `validator_index` does not exist, does not have duties or `Self` is
    /// non-initialized.
    pub fn get_attestation_duties(&self, validator_index: usize) -> Option<AttestationDuty> {
        let i = self.shuffled_position(validator_index)?;

        (0..self.epoch_committee_count())
            .map(|nth_committee| (nth_committee, self.compute_committee_range(nth_committee)))
            .find(|(_, range)| {
                if let Some(range) = range {
                    range.start <= i && range.end > i
                } else {
                    false
                }
            })
            .and_then(|(nth_committee, range)| {
                let (slot, index) = self.convert_to_slot_and_index(nth_committee as u64)?;
                let range = range?;
                let committee_position = i - range.start;
                let committee_len = range.end - range.start;

                Some(AttestationDuty {
                    slot,
                    index,
                    committee_position,
                    committee_len,
                    committees_at_slot: self.committees_per_slot(),
                })
            })
    }

    /// Convert an index addressing the list of all epoch committees into a slot and per-slot index.
    fn convert_to_slot_and_index(
        &self,
        global_committee_index: u64,
    ) -> Option<(Slot, CommitteeIndex)> {
        let epoch_start_slot = self.initialized_epoch?.start_slot(self.slots_per_epoch);
        let slot_offset = global_committee_index / self.committees_per_slot;
        let index = global_committee_index % self.committees_per_slot;
        Some((epoch_start_slot.safe_add(slot_offset).ok()?, index))
    }

    /// Returns the number of active validators in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }

    /// Returns the total number of committees in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    ///
    /// Spec v0.12.1
    pub fn epoch_committee_count(&self) -> usize {
        epoch_committee_count(
            self.committees_per_slot as usize,
            self.slots_per_epoch as usize,
        )
    }

    /// Returns the number of committees per slot for this cache's epoch.
    pub fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// Returns a slice of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// Spec v0.12.1
    fn compute_committee(&self, index: usize) -> Option<&[usize]> {
        self.shuffling.get(self.compute_committee_range(index)?)
    }

    /// Returns a range of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// To avoid a divide-by-zero, returns `None` if `self.committee_count` is zero.
    ///
    /// Will also return `None` if the index is out of bounds.
    ///
    /// Spec v0.12.1
    fn compute_committee_range(&self, index: usize) -> Option<Range<usize>> {
        compute_committee_range_in_epoch(self.epoch_committee_count(), index, self.shuffling.len())
    }

    /// Returns the index of some validator in `self.shuffling`.
    ///
    /// Always returns `None` for a non-initialized epoch.
    pub fn shuffled_position(&self, validator_index: usize) -> Option<usize> {
        self.shuffling_positions
            .get(validator_index)?
            .0
            .map(|p| p.get() - 1)
    }
}

/// Computes the position of the given `committee_index` with respect to all committees in the
/// epoch.
///
/// The return result may be used to provide input to the `compute_committee_range_in_epoch`
/// function.
pub fn compute_committee_index_in_epoch(
    slot: Slot,
    slots_per_epoch: usize,
    committees_per_slot: usize,
    committee_index: usize,
) -> usize {
    (slot.as_usize() % slots_per_epoch) * committees_per_slot + committee_index
}

/// Computes the range for slicing the shuffled indices to determine the members of a committee.
///
/// The `index_in_epoch` parameter can be computed computed using
/// `compute_committee_index_in_epoch`.
pub fn compute_committee_range_in_epoch(
    epoch_committee_count: usize,
    index_in_epoch: usize,
    shuffling_len: usize,
) -> Option<Range<usize>> {
    if epoch_committee_count == 0 || index_in_epoch >= epoch_committee_count {
        return None;
    }

    let start = (shuffling_len * index_in_epoch) / epoch_committee_count;
    let end = (shuffling_len * (index_in_epoch + 1)) / epoch_committee_count;

    Some(start..end)
}

/// Returns the total number of committees in an epoch.
pub fn epoch_committee_count(committees_per_slot: usize, slots_per_epoch: usize) -> usize {
    committees_per_slot * slots_per_epoch
}

/// Returns a list of all `validators` indices where the validator is active at the given
/// `epoch`.
///
/// Spec v0.12.1
pub fn get_active_validator_indices(validators: &[Validator], epoch: Epoch) -> Vec<usize> {
    let mut active = Vec::with_capacity(validators.len());

    for (index, validator) in validators.iter().enumerate() {
        if validator.is_active_at(epoch) {
            active.push(index)
        }
    }

    active.shrink_to_fit();

    active
}

#[cfg(feature = "arbitrary-fuzz")]
impl arbitrary::Arbitrary<'_> for CommitteeCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}

/// This is a shim struct to ensure that we can encode a `Vec<Option<NonZeroUsize>>` an SSZ union
/// with a four-byte selector. The SSZ specification changed from four bytes to one byte during 2021
/// and we use this shim to avoid breaking the Lighthouse database.
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct NonZeroUsizeOption(Option<NonZeroUsize>);

impl From<Option<NonZeroUsize>> for NonZeroUsizeOption {
    fn from(opt: Option<NonZeroUsize>) -> Self {
        Self(opt)
    }
}

impl Encode for NonZeroUsizeOption {
    fn is_ssz_fixed_len() -> bool {
        four_byte_option_non_zero_usize::encode::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        four_byte_option_non_zero_usize::encode::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        four_byte_option_non_zero_usize::encode::ssz_bytes_len(&self.0)
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        four_byte_option_non_zero_usize::encode::ssz_append(&self.0, buf)
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        four_byte_option_non_zero_usize::encode::as_ssz_bytes(&self.0)
    }
}

impl Decode for NonZeroUsizeOption {
    fn is_ssz_fixed_len() -> bool {
        four_byte_option_non_zero_usize::decode::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        four_byte_option_non_zero_usize::decode::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        four_byte_option_non_zero_usize::decode::from_ssz_bytes(bytes).map(Self)
    }
}
