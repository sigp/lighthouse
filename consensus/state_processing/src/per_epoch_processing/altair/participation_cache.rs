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

use crate::common::altair::{get_base_reward, BaseRewardPerIncrement};
use safe_arith::{ArithError, SafeArith};
use types::milhouse::update_map::{MaxMap, UpdateMap};
use types::{
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
    BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, ParticipationFlags, RelativeEpoch,
    Unsigned, Validator,
};
use vec_map::VecMap;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidFlagIndex(usize),
    NoUnslashedParticipatingIndices,
    MissingValidator(usize),
    BeaconState(BeaconStateError),
    Arith(ArithError),
    InvalidValidatorIndex(usize),
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Self::Arith(e)
    }
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
    fn new(spec: &ChainSpec) -> Self {
        let zero_balance = Balance::zero(spec.effective_balance_increment);

        Self {
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
        validator: &Validator,
        epoch_participation: &ParticipationFlags,
        // FIXME(sproul): remove state argument
        _state: &BeaconState<T>,
        current_epoch: Epoch,
        relative_epoch: RelativeEpoch,
    ) -> Result<(), BeaconStateError> {
        // Sanity check to ensure the validator is active.
        let epoch = relative_epoch.into_epoch(current_epoch);
        if !validator.is_active_at(epoch) {
            return Err(BeaconStateError::ValidatorIsInactive { val_index });
        }

        // All active validators increase the total active balance.
        self.total_active_balance
            .safe_add_assign(validator.effective_balance)?;

        // Only unslashed validators may proceed.
        if validator.slashed {
            return Ok(());
        }

        // Iterate through all the flags and increment the total flag balances for whichever flags
        // are set for `val_index`.
        for (flag, balance) in self.total_flag_balances.iter_mut().enumerate() {
            if epoch_participation.has_flag(flag)? {
                balance.safe_add_assign(validator.effective_balance)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ValidatorInfo {
    pub effective_balance: u64,
    pub base_reward: u64,
    pub is_eligible: bool,
    pub is_slashed: bool,
    pub is_active_current_epoch: bool,
    pub is_active_previous_epoch: bool,
    pub previous_epoch_participation: ParticipationFlags,
}

impl ValidatorInfo {
    #[inline]
    pub fn is_unslashed_participating_index(&self, flag_index: usize) -> Result<bool, Error> {
        Ok(self.is_active_previous_epoch
            && !self.is_slashed
            && self
                .previous_epoch_participation
                .has_flag(flag_index)
                .map_err(|_| Error::InvalidFlagIndex(flag_index))?)
    }
}

/// Single `HashMap` for validator info relevant to `process_epoch`.
#[derive(Debug, PartialEq)]
struct ValidatorInfoCache {
    info: Vec<Option<ValidatorInfo>>,
}

impl ValidatorInfoCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            info: vec![None; capacity],
        }
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
    /// Caches validator information relevant to `process_epoch`.
    validators: ValidatorInfoCache,
    /// Caches the result of the `get_eligible_validator_indices` function.
    eligible_indices: Vec<usize>,
    /// Caches the indices and effective balances of validators that need to be processed by
    /// `process_slashings`.
    process_slashings_indices: Vec<(usize, u64)>,
    /// Updates to the inactivity scores if we are definitely not in an inactivity leak.
    pub inactivity_score_updates: Option<MaxMap<VecMap<u64>>>,
}

impl ParticipationCache {
    /// Instantiate `Self`, returning a fully initialized cache.
    ///
    /// ## Errors
    ///
    /// - The provided `state` **must** be an Altair state. An error will be returned otherwise.
    pub fn new<T: EthSpec>(state: &BeaconState<T>, spec: &ChainSpec) -> Result<Self, Error> {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        // Both the current/previous epoch participations are set to a capacity that is slightly
        // larger than required. The difference will be due slashed-but-active validators.
        let mut current_epoch_participation = SingleEpochParticipationCache::new(spec);
        let mut previous_epoch_participation = SingleEpochParticipationCache::new(spec);

        let mut validators = ValidatorInfoCache::new(state.validators().len());

        let current_epoch_total_active_balance = state.get_total_active_balance()?;
        let base_reward_per_increment =
            BaseRewardPerIncrement::new(current_epoch_total_active_balance, spec)?;

        // Contains the set of validators which are either:
        //
        // - Active in the previous epoch.
        // - Slashed, but not yet withdrawable.
        //
        // Using the full length of `state.validators` is almost always overkill, but it ensures no
        // reallocations.
        let mut eligible_indices = Vec::with_capacity(state.validators().len());

        let mut process_slashings_indices = vec![];

        // Fast path for inactivity scores update when we are definitely not in an inactivity leak.
        // This breaks the dependence of `process_inactivity_updates` on the finalization
        // re-calculation.
        let definitely_not_in_inactivity_leak =
            state.finalized_checkpoint().epoch + spec.min_epochs_to_inactivity_penalty + 1
                >= state.current_epoch();
        let mut inactivity_score_updates = MaxMap::default();

        // Iterate through all validators, updating:
        //
        // 1. Validator participation for current and previous epochs.
        // 2. The "eligible indices".
        //
        // Care is taken to ensure that the ordering of `eligible_indices` is the same as the
        // `get_eligible_validator_indices` function in the spec.
        let iter = state
            .validators()
            .iter()
            .zip(state.current_epoch_participation()?)
            .zip(state.previous_epoch_participation()?)
            .zip(state.inactivity_scores()?)
            .enumerate();
        for (val_index, (((val, curr_epoch_flags), prev_epoch_flags), inactivity_score)) in iter {
            let is_active_current_epoch = val.is_active_at(current_epoch);
            let is_active_previous_epoch = val.is_active_at(previous_epoch);
            let is_eligible = state.is_eligible_validator(previous_epoch, val);

            if is_active_current_epoch {
                current_epoch_participation.process_active_validator(
                    val_index,
                    val,
                    curr_epoch_flags,
                    state,
                    current_epoch,
                    RelativeEpoch::Current,
                )?;
            }

            if is_active_previous_epoch {
                assert!(is_eligible);

                previous_epoch_participation.process_active_validator(
                    val_index,
                    val,
                    prev_epoch_flags,
                    state,
                    current_epoch,
                    RelativeEpoch::Previous,
                )?;
            }

            if val.slashed
                && current_epoch.safe_add(T::EpochsPerSlashingsVector::to_u64().safe_div(2)?)?
                    == val.withdrawable_epoch
            {
                process_slashings_indices.push((val_index, val.effective_balance));
            }

            // Note: a validator might still be "eligible" whilst returning `false` to
            // `Validator::is_active_at`. It's also possible for a validator to be active
            // in the current epoch without being eligible (if it was just activated).
            if is_eligible {
                eligible_indices.push(val_index);
            }

            let mut validator_info = ValidatorInfo {
                effective_balance: val.effective_balance,
                base_reward: 0, // not read
                is_eligible,
                is_slashed: val.slashed,
                is_active_current_epoch,
                is_active_previous_epoch,
                previous_epoch_participation: *prev_epoch_flags,
            };

            // Calculate inactivity updates.
            if is_eligible && definitely_not_in_inactivity_leak {
                let mut new_inactivity_score =
                    if validator_info.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
                        inactivity_score.saturating_sub(1)
                    } else {
                        inactivity_score.safe_add(spec.inactivity_score_bias)?
                    };

                // Decrease the score of all validators for forgiveness when not during a leak
                new_inactivity_score =
                    new_inactivity_score.saturating_sub(spec.inactivity_score_recovery_rate);

                if new_inactivity_score != *inactivity_score {
                    inactivity_score_updates.insert(val_index, new_inactivity_score);
                }
            }

            if is_eligible || is_active_current_epoch {
                let effective_balance = val.effective_balance;
                let base_reward =
                    get_base_reward(effective_balance, base_reward_per_increment, spec)?;
                validator_info.base_reward = base_reward;
                validators.info[val_index] = Some(validator_info);
            }
        }

        // Sanity check total active balance.
        // FIXME(sproul): assert
        assert_eq!(
            current_epoch_participation.total_active_balance.get(),
            current_epoch_total_active_balance
        );

        Ok(Self {
            current_epoch,
            current_epoch_participation,
            previous_epoch,
            previous_epoch_participation,
            validators,
            eligible_indices,
            process_slashings_indices,
            inactivity_score_updates: definitely_not_in_inactivity_leak
                .then(|| inactivity_score_updates),
        })
    }

    /// Equivalent to the specification `get_eligible_validator_indices` function.
    pub fn eligible_validator_indices(&self) -> &[usize] {
        &self.eligible_indices
    }

    pub fn process_slashings_indices(&mut self) -> Vec<(usize, u64)> {
        std::mem::take(&mut self.process_slashings_indices)
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
        self.previous_epoch_flag_attesting_balance(TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn previous_epoch_source_attesting_balance(&self) -> Result<u64, Error> {
        self.previous_epoch_flag_attesting_balance(TIMELY_SOURCE_FLAG_INDEX)
    }

    pub fn previous_epoch_head_attesting_balance(&self) -> Result<u64, Error> {
        self.previous_epoch_flag_attesting_balance(TIMELY_HEAD_FLAG_INDEX)
    }

    pub fn previous_epoch_flag_attesting_balance(&self, flag_index: usize) -> Result<u64, Error> {
        self.previous_epoch_participation
            .total_flag_balance(flag_index)
    }

    /*
     * Active/Unslashed
     */

    pub fn is_active_unslashed_in_previous_epoch(&self, val_index: usize) -> bool {
        self.get_validator(val_index).map_or(false, |validator| {
            validator.is_active_previous_epoch && !validator.is_slashed
        })
    }

    pub fn is_active_unslashed_in_current_epoch(&self, val_index: usize) -> bool {
        self.get_validator(val_index).map_or(false, |validator| {
            validator.is_active_current_epoch && !validator.is_slashed
        })
    }

    pub fn get_validator(&self, val_index: usize) -> Result<&ValidatorInfo, Error> {
        self.validators
            .info
            .get(val_index)
            .ok_or(Error::MissingValidator(val_index))?
            .as_ref()
            .ok_or(Error::MissingValidator(val_index))
    }

    /*
     * Flags
     */
    /// Always returns false for a slashed validator.
    pub fn is_previous_epoch_timely_source_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, Error> {
        self.get_validator(val_index)
            .map_or(Ok(false), |validator| {
                Ok(!validator.is_slashed
                    && validator
                        .previous_epoch_participation
                        .has_flag(TIMELY_SOURCE_FLAG_INDEX)
                        .map_err(|_| Error::InvalidFlagIndex(TIMELY_SOURCE_FLAG_INDEX))?)
            })
    }

    /// Always returns false for a slashed validator.
    pub fn is_previous_epoch_timely_target_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, Error> {
        self.get_validator(val_index)
            .map_or(Ok(false), |validator| {
                Ok(!validator.is_slashed
                    && validator
                        .previous_epoch_participation
                        .has_flag(TIMELY_TARGET_FLAG_INDEX)
                        .map_err(|_| Error::InvalidFlagIndex(TIMELY_TARGET_FLAG_INDEX))?)
            })
    }

    /// Always returns false for a slashed validator.
    pub fn is_previous_epoch_timely_head_attester(&self, val_index: usize) -> Result<bool, Error> {
        self.get_validator(val_index)
            .map_or(Ok(false), |validator| {
                Ok(!validator.is_slashed
                    && validator
                        .previous_epoch_participation
                        .has_flag(TIMELY_HEAD_FLAG_INDEX)
                        .map_err(|_| Error::InvalidFlagIndex(TIMELY_TARGET_FLAG_INDEX))?)
            })
    }

    /// Always returns false for a slashed validator.
    pub fn is_current_epoch_timely_target_attester(
        &self,
        _val_index: usize,
    ) -> Result<bool, Error> {
        // FIXME(sproul): decide whether it's worth storing the current epoch participation flags
        // *just* for this call. Perhaps the validator API could source it from the state directly.
        Ok(false)
    }
}
