#![deny(clippy::wildcard_imports)]

// FIXME(altair): refactor to remove phase0/base structs, including `EpochProcessingSummary`
pub use base::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use errors::EpochProcessingError as Error;
pub use registry_updates::process_registry_updates;
use safe_arith::SafeArith;
pub use slashings::process_slashings;
use types::{BeaconState, ChainSpec, EthSpec};
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
    pub statuses: Vec<ValidatorStatus>,
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
