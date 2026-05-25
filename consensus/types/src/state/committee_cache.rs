use std::{num::NonZeroUsize, ops::Range, sync::Arc};

use educe::Educe;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode, four_byte_option_impl};
use ssz_derive::{Decode, Encode};
use swap_or_not_shuffle::shuffle_list;

use crate::{
    attestation::{AttestationDuty, BeaconCommittee, CommitteeIndex},
    core::{ChainSpec, Domain, Epoch, EthSpec, Slot},
    state::{BeaconState, BeaconStateError},
    validator::Validator,
};

// Define "legacy" implementations of `Option<Epoch>`, `Option<NonZeroUsize>` which use four bytes
// for encoding the union selector.
four_byte_option_impl!(four_byte_option_epoch, Epoch);
four_byte_option_impl!(four_byte_option_non_zero_usize, NonZeroUsize);

/// Computes and stores the shuffling for an epoch. Provides various getters to allow callers to
/// read the committees for the given epoch.
#[derive(Educe, Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
#[educe(PartialEq)]
pub struct CommitteeCache {
    #[ssz(with = "four_byte_option_epoch")]
    initialized_epoch: Option<Epoch>,
    shuffling: Vec<usize>,
    #[educe(PartialEq(method(compare_shuffling_positions)))]
    shuffling_positions: Vec<NonZeroUsizeOption>,
    committees_per_slot: u64,
    slots_per_epoch: u64,
}

/// Equivalence function for `shuffling_positions` that ignores trailing `None` entries.
///
/// It can happen that states from different epochs computing the same cache have different
/// numbers of validators in `state.validators()` due to recent deposits. These new validators
/// cannot be active however and will always be omitted from the shuffling. This function checks
/// that two lists of shuffling positions are equivalent by ensuring that they are identical on all
/// common entries, and that new entries at the end are all `None`.
///
/// In practice this is only used in tests.
#[allow(clippy::indexing_slicing)]
fn compare_shuffling_positions(xs: &Vec<NonZeroUsizeOption>, ys: &Vec<NonZeroUsizeOption>) -> bool {
    use std::cmp::Ordering;

    let (shorter, longer) = match xs.len().cmp(&ys.len()) {
        Ordering::Equal => {
            return xs == ys;
        }
        Ordering::Less => (xs, ys),
        Ordering::Greater => (ys, xs),
    };
    shorter == &longer[..shorter.len()]
        && longer[shorter.len()..]
            .iter()
            .all(|new| *new == NonZeroUsizeOption(None))
}

impl CommitteeCache {
    /// Return a new, fully initialized cache.
    ///
    /// The epoch must be within the range that the state can service: historic epochs with
    /// available randao data, up to `current_epoch + 1` (the "next" epoch).
    ///
    /// Spec v0.12.1
    pub fn initialized<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Arc<CommitteeCache>, BeaconStateError> {
        // Check that the cache is being built for an in-range epoch.
        //
        // We allow caches to be constructed for historic epochs, per:
        //
        // https://github.com/sigp/lighthouse/issues/3270
        let reqd_randao_epoch = epoch
            .saturating_sub(spec.min_seed_lookahead)
            .saturating_sub(1u64);

        if reqd_randao_epoch < state.min_randao_epoch()
            || epoch
                > state
                    .current_epoch()
                    .safe_add(1u64)
                    .map_err(BeaconStateError::ArithError)?
        {
            return Err(BeaconStateError::EpochOutOfBounds);
        }

        Self::initialized_unchecked(state, epoch, spec)
    }

    /// Return a new, fully initialized cache for a lookahead epoch.
    ///
    /// Like [`initialized`](Self::initialized), but allows epochs beyond `current_epoch + 1`.
    /// The only bound enforced is that the required randao seed is available in the state.
    ///
    /// This is used by PTC window computation, which needs committee shufflings for
    /// `current_epoch + 1 + MIN_SEED_LOOKAHEAD`.
    pub fn initialized_for_lookahead<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Arc<CommitteeCache>, BeaconStateError> {
        let reqd_randao_epoch = epoch
            .saturating_sub(spec.min_seed_lookahead)
            .saturating_sub(1u64);

        if reqd_randao_epoch < state.min_randao_epoch() {
            return Err(BeaconStateError::EpochOutOfBounds);
        }

        Self::initialized_unchecked(state, epoch, spec)
    }

    /// Core committee cache construction. Callers are responsible for bounds-checking `epoch`.
    fn initialized_unchecked<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Arc<CommitteeCache>, BeaconStateError> {
        // May cause divide-by-zero errors.
        if E::slots_per_epoch() == 0 {
            return Err(BeaconStateError::ZeroSlotsPerEpoch);
        }

        // The use of `NonZeroUsize` reduces the maximum number of possible validators by one.
        if state.validators().len() == usize::MAX {
            return Err(BeaconStateError::TooManyValidators);
        }

        let active_validator_indices = get_active_validator_indices(state.validators(), epoch);

        if active_validator_indices.is_empty() {
            return Err(BeaconStateError::InsufficientValidators);
        }

        let committees_per_slot =
            E::get_committee_count_per_slot(active_validator_indices.len(), spec)
                .map_err(BeaconStateError::ArithError)? as u64;

        let seed = state.get_seed(epoch, Domain::BeaconAttester, spec)?;

        let shuffling = shuffle_list(
            active_validator_indices,
            spec.shuffle_round_count,
            &seed[..],
            false,
        )
        .ok_or(BeaconStateError::UnableToShuffle)?;

        let mut shuffling_positions = vec![<_>::default(); state.validators().len()];
        for (i, &v) in shuffling.iter().enumerate() {
            *shuffling_positions
                .get_mut(v)
                .ok_or(BeaconStateError::ShuffleIndexOutOfBounds(v))? =
                NonZeroUsize::new(i.safe_add(1).map_err(BeaconStateError::ArithError)?).into();
        }

        Ok(Arc::new(CommitteeCache {
            initialized_epoch: Some(epoch),
            shuffling,
            shuffling_positions,
            committees_per_slot,
            slots_per_epoch: E::slots_per_epoch(),
        }))
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
    ) -> Option<BeaconCommittee<'_>> {
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
        )
        .ok()?;
        let committee = self.compute_committee(committee_index).ok()??;

        Some(BeaconCommittee {
            slot,
            index,
            committee,
        })
    }

    /// Get all the Beacon committees at a given `slot`.
    ///
    /// Committees are sorted by ascending index order 0..committees_per_slot
    pub fn get_beacon_committees_at_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<BeaconCommittee<'_>>, BeaconStateError> {
        if self.initialized_epoch.is_none() {
            return Err(BeaconStateError::CommitteeCacheUninitialized(None));
        }

        (0..self.committees_per_slot())
            .map(|index| {
                self.get_beacon_committee(slot, index)
                    .ok_or(BeaconStateError::NoCommittee { slot, index })
            })
            .collect()
    }

    /// Returns all committees for `self.initialized_epoch`.
    pub fn get_all_beacon_committees(&self) -> Result<Vec<BeaconCommittee<'_>>, BeaconStateError> {
        let initialized_epoch = self
            .initialized_epoch
            .ok_or(BeaconStateError::CommitteeCacheUninitialized(None))?;

        let capacity = self.epoch_committee_count()?;
        initialized_epoch.slot_iter(self.slots_per_epoch).try_fold(
            Vec::with_capacity(capacity),
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
    pub fn get_attestation_duties(
        &self,
        validator_index: usize,
    ) -> Result<Option<AttestationDuty>, ArithError> {
        let Some(i) = self.shuffled_position(validator_index) else {
            return Ok(None);
        };

        for nth_committee in 0..self.epoch_committee_count()? {
            let Some(range) = self.compute_committee_range(nth_committee)? else {
                continue;
            };

            if range.start <= i && range.end > i {
                let Some((slot, index)) = self.convert_to_slot_and_index(nth_committee as u64)?
                else {
                    return Ok(None);
                };

                let committee_position = i.safe_sub(range.start)?;
                let committee_len = range.end.safe_sub(range.start)?;

                return Ok(Some(AttestationDuty {
                    slot,
                    index,
                    committee_position,
                    committee_len,
                    committees_at_slot: self.committees_per_slot(),
                }));
            }
        }

        Ok(None)
    }

    /// Convert an index addressing the list of all epoch committees into a slot and per-slot index.
    fn convert_to_slot_and_index(
        &self,
        global_committee_index: u64,
    ) -> Result<Option<(Slot, CommitteeIndex)>, ArithError> {
        let Some(epoch) = self.initialized_epoch else {
            return Ok(None);
        };
        let epoch_start_slot = epoch.start_slot(self.slots_per_epoch);
        let slot_offset = global_committee_index.safe_div(self.committees_per_slot)?;
        let index = global_committee_index.safe_rem(self.committees_per_slot)?;
        Ok(Some((epoch_start_slot.safe_add(slot_offset)?, index)))
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
    pub fn epoch_committee_count(&self) -> Result<usize, ArithError> {
        (self.committees_per_slot as usize).safe_mul(self.slots_per_epoch as usize)
    }

    /// Returns the number of committees per slot for this cache's epoch.
    pub fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// Returns a slice of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// Spec v0.12.1
    fn compute_committee(&self, index: usize) -> Result<Option<&[usize]>, ArithError> {
        if let Some(range) = self.compute_committee_range(index)? {
            Ok(self.shuffling.get(range))
        } else {
            Ok(None)
        }
    }

    /// Returns a range of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// To avoid a divide-by-zero, returns `Ok(None)` if `self.committee_count` is zero.
    ///
    /// Will also return `Ok(None)` if the index is out of bounds.
    ///
    /// Spec v0.12.1
    fn compute_committee_range(&self, index: usize) -> Result<Option<Range<usize>>, ArithError> {
        compute_committee_range_in_epoch(self.epoch_committee_count()?, index, self.shuffling.len())
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
) -> Result<usize, ArithError> {
    (slot.as_usize().safe_rem(slots_per_epoch)?)
        .safe_mul(committees_per_slot)?
        .safe_add(committee_index)
}

/// Computes the range for slicing the shuffled indices to determine the members of a committee.
///
/// The `index_in_epoch` parameter can be computed computed using
/// `compute_committee_index_in_epoch`.
pub fn compute_committee_range_in_epoch(
    epoch_committee_count: usize,
    index_in_epoch: usize,
    shuffling_len: usize,
) -> Result<Option<Range<usize>>, ArithError> {
    if epoch_committee_count == 0 || index_in_epoch >= epoch_committee_count {
        return Ok(None);
    }

    let start = (shuffling_len.safe_mul(index_in_epoch))?.safe_div(epoch_committee_count)?;
    let end =
        (shuffling_len.safe_mul(index_in_epoch.safe_add(1)?))?.safe_div(epoch_committee_count)?;

    Ok(Some(start..end))
}

/// Returns a list of all `validators` indices where the validator is active at the given
/// `epoch`.
///
/// Spec v0.12.1
pub fn get_active_validator_indices<'a, V, I>(validators: V, epoch: Epoch) -> Vec<usize>
where
    V: IntoIterator<Item = &'a Validator, IntoIter = I>,
    I: ExactSizeIterator + Iterator<Item = &'a Validator>,
{
    let iter = validators.into_iter();

    let mut active = Vec::with_capacity(iter.len());

    for (index, validator) in iter.enumerate() {
        if validator.is_active_at(epoch) {
            active.push(index)
        }
    }

    active
}

#[cfg(feature = "arbitrary")]
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
