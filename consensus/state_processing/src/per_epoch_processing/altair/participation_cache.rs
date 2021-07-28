//! Provides the `ParticipationCache`, a custom Lighthouse cache which attempts to reduce CPU and
//! memory usage by:
//!
//! - Caching a map of `validator_index -> participation_flags` for all active validators in the
//!   previous and current epochs.
//! - Caching the total balances of:
//!   - All active validators.
//!   - All active validators matching each of the three "timely" flags.
//! - Caching the "eligible" validators.
//!
//! Additionally, this cache is returned from the `altair::process_epoch` function and can be used
//! to get useful summaries about the validator participation in an epoch.

use safe_arith::{ArithError, SafeArith};
use std::collections::HashMap;
use types::{
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
    BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, ParticipationFlags, RelativeEpoch,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidFlagIndex(usize),
}

/// A balance which will never be below the specified `minimum`.
///
/// This is an effort to ensure the `EFFECTIVE_BALANCE_INCREMENT` minimum is always respected.
#[derive(PartialEq, Debug, Clone, Copy)]
struct Balance {
    raw: u64,
    minimum: u64,
}

impl Balance {
    /// Initialize the balance to `0`, or the given `minimum`.
    pub fn zero(minimum: u64) -> Self {
        Self { raw: 0, minimum }
    }

    /// Returns the balance with respect to the initialization `minimum`.
    pub fn get(&self) -> u64 {
        std::cmp::max(self.raw, self.minimum)
    }

    /// Add-assign to the balance.
    pub fn safe_add_assign(&mut self, other: u64) -> Result<(), ArithError> {
        self.raw.safe_add_assign(other)
    }
}

/// Caches the participation values for one epoch (either the previous or current).
#[derive(PartialEq, Debug)]
struct SingleEpochParticipationCache {
    /// Maps an active validator index to their participation flags.
    ///
    /// To reiterate, only active and unslashed validator indices are stored in this map.
    ///
    /// ## Note
    ///
    /// It would be ideal to maintain a reference to the `BeaconState` here rather than copying the
    /// `ParticipationFlags`, however that would cause us to run into mutable reference limitations
    /// upstream.
    unslashed_participating_indices: HashMap<usize, ParticipationFlags>,
    /// Stores the sum of the balances for all validators in `self.unslashed_participating_indices`
    /// for all flags in `NUM_FLAG_INDICES`.
    ///
    /// A flag balance is only incremented if a validator is in that flag set.
    total_flag_balances: [Balance; NUM_FLAG_INDICES],
    /// Stores the sum of all balances of all validators in `self.unslashed_participating_indices`
    /// (regardless of which flags are set).
    total_active_balance: Balance,
}

impl SingleEpochParticipationCache {
    fn new(hashmap_len: usize, spec: &ChainSpec) -> Self {
        let zero_balance = Balance::zero(spec.effective_balance_increment);

        Self {
            unslashed_participating_indices: HashMap::with_capacity(hashmap_len),
            total_flag_balances: [zero_balance; NUM_FLAG_INDICES],
            total_active_balance: zero_balance,
        }
    }

    /// Returns the total balance of attesters who have `flag_index` set.
    fn total_flag_balance(&self, flag_index: usize) -> Result<u64, Error> {
        self.total_flag_balances
            .get(flag_index)
            .map(Balance::get)
            .ok_or(Error::InvalidFlagIndex(flag_index))
    }

    /// Returns `true` if `val_index` is active, unslashed and has `flag_index` set.
    ///
    /// ## Errors
    ///
    /// May return an error if `flag_index` is out-of-bounds.
    fn has_flag(&self, val_index: usize, flag_index: usize) -> Result<bool, Error> {
        if let Some(participation_flags) = self.unslashed_participating_indices.get(&val_index) {
            participation_flags
                .has_flag(flag_index)
                .map_err(|_| Error::InvalidFlagIndex(flag_index))
        } else {
            Ok(false)
        }
    }

    /// Process an **active** validator, reading from the `state` with respect to the
    /// `relative_epoch`.
    ///
    /// ## Errors
    ///
    /// - The provided `state` **must** be Altair. An error will be returned otherwise.
    /// - An error will be returned if the `val_index` validator is inactive at the given
    ///     `relative_epoch`.
    fn process_active_validator<T: EthSpec>(
        &mut self,
        val_index: usize,
        state: &BeaconState<T>,
        relative_epoch: RelativeEpoch,
    ) -> Result<(), BeaconStateError> {
        let val_balance = state.get_effective_balance(val_index)?;
        let validator = state.get_validator(val_index)?;

        // Sanity check to ensure the validator is active.
        let epoch = relative_epoch.into_epoch(state.current_epoch());
        if !validator.is_active_at(epoch) {
            return Err(BeaconStateError::ValidatorIsInactive { val_index });
        }

        let epoch_participation = match relative_epoch {
            RelativeEpoch::Current => state.current_epoch_participation(),
            RelativeEpoch::Previous => state.previous_epoch_participation(),
            _ => Err(BeaconStateError::EpochOutOfBounds),
        }?
        .get(val_index)
        .ok_or(BeaconStateError::ParticipationOutOfBounds(val_index))?;

        // All active validators increase the total active balance.
        self.total_active_balance.safe_add_assign(val_balance)?;

        // Only unslashed validators may proceed.
        if validator.slashed {
            return Ok(());
        }

        // Add their `ParticipationFlags` to the map.
        self.unslashed_participating_indices
            .insert(val_index, *epoch_participation);

        // Iterate through all the flags and increment the total flag balances for whichever flags
        // are set for `val_index`.
        for (flag, balance) in self.total_flag_balances.iter_mut().enumerate() {
            if epoch_participation.has_flag(flag)? {
                balance.safe_add_assign(val_balance)?;
            }
        }

        Ok(())
    }
}

/// Maintains a cache to be used during `altair::process_epoch`.
#[derive(PartialEq, Debug)]
pub struct ParticipationCache {
    current_epoch: Epoch,
    /// Caches information about active validators pertaining to `self.current_epoch`.
    current_epoch_participation: SingleEpochParticipationCache,
    previous_epoch: Epoch,
    /// Caches information about active validators pertaining to `self.previous_epoch`.
    previous_epoch_participation: SingleEpochParticipationCache,
    /// Caches the result of the `get_eligible_validator_indices` function.
    eligible_indices: Vec<usize>,
}

impl ParticipationCache {
    /// Instantiate `Self`, returning a fully initialized cache.
    ///
    /// ## Errors
    ///
    /// - The provided `state` **must** be an Altair state. An error will be returned otherwise.
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        let num_previous_epoch_active_vals = state
            .get_cached_active_validator_indices(RelativeEpoch::Previous)?
            .len();
        let num_current_epoch_active_vals = state
            .get_cached_active_validator_indices(RelativeEpoch::Current)?
            .len();

        // Both the current/previous epoch participations are set to a capacity that is slightly
        // larger than required. The difference will be due slashed-but-active validators.
        let mut current_epoch_participation =
            SingleEpochParticipationCache::new(num_current_epoch_active_vals, spec);
        let mut previous_epoch_participation =
            SingleEpochParticipationCache::new(num_previous_epoch_active_vals, spec);
        // Contains the set of validators which are either:
        //
        // - Active in the previous epoch.
        // - Slashed, but not yet withdrawable.
        //
        // Using the full length of `state.validators` is almost always overkill, but it ensures no
        // reallocations.
        let mut eligible_indices = Vec::with_capacity(state.validators().len());

        // Iterate through all validators, updating:
        //
        // 1. Validator participation for current and previous epochs.
        // 2. The "eligible indices".
        //
        // Care is taken to ensure that the ordering of `eligible_indices` is the same as the
        // `get_eligible_validator_indices` function in the spec.
        for (val_index, val) in state.validators().iter().enumerate() {
            if val.is_active_at(current_epoch) {
                current_epoch_participation.process_active_validator(
                    val_index,
                    state,
                    RelativeEpoch::Current,
                )?;
            }

            if val.is_active_at(previous_epoch) {
                previous_epoch_participation.process_active_validator(
                    val_index,
                    state,
                    RelativeEpoch::Previous,
                )?;
            }

            // Note: a validator might still be "eligible" whilst returning `false` to
            // `Validator::is_active_at`.
            if state.is_eligible_validator(val_index)? {
                eligible_indices.push(val_index)
            }
        }

        Ok(Self {
            current_epoch,
            current_epoch_participation,
            previous_epoch,
            previous_epoch_participation,
            eligible_indices,
        })
    }

    /// Equivalent to the specification `get_eligible_validator_indices` function.
    pub fn eligible_validator_indices(&self) -> &[usize] {
        &self.eligible_indices
    }

    /// Equivalent to the `get_unslashed_participating_indices` function in the specification.
    pub fn get_unslashed_participating_indices(
        &self,
        flag_index: usize,
        epoch: Epoch,
    ) -> Result<UnslashedParticipatingIndices, BeaconStateError> {
        let participation = if epoch == self.current_epoch {
            &self.current_epoch_participation
        } else if epoch == self.previous_epoch {
            &self.previous_epoch_participation
        } else {
            return Err(BeaconStateError::EpochOutOfBounds);
        };

        Ok(UnslashedParticipatingIndices {
            participation,
            flag_index,
        })
    }

    /*
     * Balances
     */

    pub fn current_epoch_total_active_balance(&self) -> u64 {
        self.current_epoch_participation.total_active_balance.get()
    }

    pub fn current_epoch_target_attesting_balance(&self) -> Result<u64, Error> {
        self.current_epoch_participation
            .total_flag_balance(TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn previous_epoch_total_active_balance(&self) -> u64 {
        self.previous_epoch_participation.total_active_balance.get()
    }

    pub fn previous_epoch_target_attesting_balance(&self) -> Result<u64, Error> {
        self.previous_epoch_participation
            .total_flag_balance(TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn previous_epoch_source_attesting_balance(&self) -> Result<u64, Error> {
        self.previous_epoch_participation
            .total_flag_balance(TIMELY_SOURCE_FLAG_INDEX)
    }

    pub fn previous_epoch_head_attesting_balance(&self) -> Result<u64, Error> {
        self.previous_epoch_participation
            .total_flag_balance(TIMELY_HEAD_FLAG_INDEX)
    }

    /*
     * Active/Unslashed
     */

    pub fn is_active_unslashed_in_previous_epoch(&self, val_index: usize) -> bool {
        self.previous_epoch_participation
            .unslashed_participating_indices
            .contains_key(&val_index)
    }

    pub fn is_active_unslashed_in_current_epoch(&self, val_index: usize) -> bool {
        self.current_epoch_participation
            .unslashed_participating_indices
            .contains_key(&val_index)
    }

    /*
     * Flags
     */

    /// Always returns false for a slashed validator.
    pub fn is_previous_epoch_timely_source_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, Error> {
        self.previous_epoch_participation
            .has_flag(val_index, TIMELY_SOURCE_FLAG_INDEX)
    }

    /// Always returns false for a slashed validator.
    pub fn is_previous_epoch_timely_target_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, Error> {
        self.previous_epoch_participation
            .has_flag(val_index, TIMELY_TARGET_FLAG_INDEX)
    }

    /// Always returns false for a slashed validator.
    pub fn is_previous_epoch_timely_head_attester(&self, val_index: usize) -> Result<bool, Error> {
        self.previous_epoch_participation
            .has_flag(val_index, TIMELY_HEAD_FLAG_INDEX)
    }

    /// Always returns false for a slashed validator.
    pub fn is_current_epoch_timely_source_attester(&self, val_index: usize) -> Result<bool, Error> {
        self.current_epoch_participation
            .has_flag(val_index, TIMELY_SOURCE_FLAG_INDEX)
    }

    /// Always returns false for a slashed validator.
    pub fn is_current_epoch_timely_target_attester(&self, val_index: usize) -> Result<bool, Error> {
        self.current_epoch_participation
            .has_flag(val_index, TIMELY_TARGET_FLAG_INDEX)
    }

    /// Always returns false for a slashed validator.
    pub fn is_current_epoch_timely_head_attester(&self, val_index: usize) -> Result<bool, Error> {
        self.current_epoch_participation
            .has_flag(val_index, TIMELY_HEAD_FLAG_INDEX)
    }
}

/// Imitates the return value of the `get_unslashed_participating_indices` in the
/// specification.
///
/// This struct exists to help make the Lighthouse code read more like the specification.
pub struct UnslashedParticipatingIndices<'a> {
    participation: &'a SingleEpochParticipationCache,
    flag_index: usize,
}

impl<'a> UnslashedParticipatingIndices<'a> {
    /// Returns `Ok(true)` if the given `val_index` is both:
    ///
    /// - An active validator.
    /// - Has `self.flag_index` set.
    pub fn contains(&self, val_index: usize) -> Result<bool, Error> {
        self.participation.has_flag(val_index, self.flag_index)
    }

    /// Returns the sum of all balances of validators which have `self.flag_index` set.
    ///
    /// ## Notes
    ///
    /// Respects the `EFFECTIVE_BALANCE_INCREMENT` minimum.
    pub fn total_balance(&self) -> Result<u64, Error> {
        self.participation
            .total_flag_balances
            .get(self.flag_index)
            .ok_or(Error::InvalidFlagIndex(self.flag_index))
            .map(Balance::get)
    }
}
