#![deny(clippy::wildcard_imports)]

// FIXME(altair): refactor to remove phase0/base structs, including `EpochProcessingSummary`
pub use base::{TotalBalances, ValidatorStatus, ValidatorStatuses};
use errors::EpochProcessingError as Error;
pub use registry_updates::process_registry_updates;
pub use slashings::process_slashings;
use types::{BeaconState, ChainSpec, EthSpec};
pub use weigh_justification_and_finalization::weigh_justification_and_finalization;

pub mod altair;
pub mod base;
pub mod errors;
pub mod registry_updates;
pub mod slashings;
pub mod tests;
pub mod validator_statuses;
pub mod weigh_justification_and_finalization;

/// Provides a summary of validator participation during the epoch.
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
    match state {
        BeaconState::Base(_) => base::process_epoch(state, spec),
        BeaconState::Altair(_) => altair::process_epoch(state, spec),
    }
}
