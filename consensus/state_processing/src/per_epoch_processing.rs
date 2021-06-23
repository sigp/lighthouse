#![deny(clippy::wildcard_imports)]

// FIXME(altair): refactor to remove phase0/base structs, including `EpochProcessingSummary`
pub use base::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use errors::EpochProcessingError as Error;
pub use registry_updates::process_registry_updates;
use safe_arith::SafeArith;
pub use slashings::process_slashings;
use types::{
    consts::altair::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
    BeaconState, BeaconStateError, ChainSpec, EthSpec,
};
pub use weigh_justification_and_finalization::weigh_justification_and_finalization;

pub mod altair;
pub mod base;
pub mod effective_balance_updates;
pub mod errors;
pub mod historical_roots_update;
pub mod registry_updates;
pub mod resets;
pub mod slashings;
pub mod tests;
pub mod validator_statuses;
pub mod weigh_justification_and_finalization;

/// Provides a summary of validator participation during the epoch.
#[derive(PartialEq, Debug)]
pub struct EpochProcessingSummary {
    pub total_balances: TotalBalances,
    pub statuses: Vec<ValidatorParticipation>,
}

#[derive(PartialEq, Debug)]
pub struct ValidatorParticipation {
    /*
     * Current Epoch
     */
    pub is_current_epoch_timely_head_attester: bool,
    pub is_current_epoch_timely_source_attester: bool,
    pub is_current_epoch_timely_target_attester: bool,
    /*
     * Previous Epoch
     */
    pub is_previous_epoch_timely_head_attester: bool,
    pub is_previous_epoch_timely_source_attester: bool,
    pub is_previous_epoch_timely_target_attester: bool,
    pub previous_epoch_inclusion_delay: Option<u64>,
}

impl ValidatorParticipation {
    pub fn altair<T: EthSpec>(state: &BeaconState<T>) -> Result<Vec<Self>, BeaconStateError> {
        let state = state.as_altair()?;

        let mut participations = Vec::with_capacity(state.validators.len());
        for i in 0..state.validators.len() {
            let current = state
                .current_epoch_participation
                .get(i)
                .ok_or(BeaconStateError::UnknownValidator(i))?;
            let previous = state
                .previous_epoch_participation
                .get(i)
                .ok_or(BeaconStateError::UnknownValidator(i))?;

            participations.push(ValidatorParticipation {
                /*
                 * Current Epoch
                 */
                is_current_epoch_timely_head_attester: current.has_flag(TIMELY_HEAD_FLAG_INDEX)?,
                is_current_epoch_timely_source_attester: current
                    .has_flag(TIMELY_SOURCE_FLAG_INDEX)?,
                is_current_epoch_timely_target_attester: current
                    .has_flag(TIMELY_TARGET_FLAG_INDEX)?,
                /*
                 * Previous Epoch
                 */
                is_previous_epoch_timely_head_attester: previous
                    .has_flag(TIMELY_HEAD_FLAG_INDEX)?,
                is_previous_epoch_timely_source_attester: previous
                    .has_flag(TIMELY_SOURCE_FLAG_INDEX)?,
                is_previous_epoch_timely_target_attester: previous
                    .has_flag(TIMELY_TARGET_FLAG_INDEX)?,
                // Field is not relevant for Altair states.
                previous_epoch_inclusion_delay: None,
            })
        }

        Ok(participations)
    }

    pub fn base(validator_statuses: &[ValidatorStatus]) -> Vec<Self> {
        validator_statuses
            .iter()
            .map(|v| {
                Self {
                    /*
                     * Current Epoch
                     */
                    // FIXME(paul): avoid making this always `false`.
                    is_current_epoch_timely_head_attester: false,
                    is_current_epoch_timely_source_attester: v.is_current_epoch_attester,
                    is_current_epoch_timely_target_attester: v.is_current_epoch_target_attester,
                    /*
                     * Previous Epoch
                     */
                    is_previous_epoch_timely_head_attester: v.is_previous_epoch_head_attester,
                    is_previous_epoch_timely_source_attester: v.is_previous_epoch_attester,
                    is_previous_epoch_timely_target_attester: v.is_previous_epoch_target_attester,
                    previous_epoch_inclusion_delay: v.inclusion_info.map(|i| i.delay),
                }
            })
            .collect()
    }
}

/// Performs per-epoch processing on some BeaconState.
///
/// Mutates the given `BeaconState`, returning early if an error is encountered. If an error is
/// returned, a state might be "half-processed" and therefore in an invalid state.
pub fn process_epoch<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<EpochProcessingSummary, Error> {
    // Verify that the `BeaconState` instantiation matches the fork at `state.slot()`.
    state
        .fork_name(spec)
        .map_err(Error::InconsistentStateFork)?;

    match state {
        BeaconState::Base(_) => base::process_epoch(state, spec),
        BeaconState::Altair(_) => altair::process_epoch(state, spec),
    }
}

/// Used to track the changes to a validator's balance.
#[derive(Default, Clone)]
pub struct Delta {
    pub rewards: u64,
    pub penalties: u64,
}

impl Delta {
    /// Reward the validator with the `reward`.
    pub fn reward(&mut self, reward: u64) -> Result<(), Error> {
        self.rewards = self.rewards.safe_add(reward)?;
        Ok(())
    }

    /// Penalize the validator with the `penalty`.
    pub fn penalize(&mut self, penalty: u64) -> Result<(), Error> {
        self.penalties = self.penalties.safe_add(penalty)?;
        Ok(())
    }

    /// Combine two deltas.
    fn combine(&mut self, other: Delta) -> Result<(), Error> {
        self.reward(other.rewards)?;
        self.penalize(other.penalties)
    }
}
