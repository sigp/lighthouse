#![deny(clippy::wildcard_imports)]

use errors::EpochProcessingError as Error;
use types::{BeaconState, ChainSpec, EthSpec};

pub mod altair;
pub mod base;
pub mod errors;
pub mod justification_and_finalization;
pub mod registry_updates;
pub mod slashings;
pub mod tests;

pub use justification_and_finalization::process_justification_and_finalization;
pub use registry_updates::process_registry_updates;
pub use slashings::process_slashings;
// FIXME(altair): refactor to remove phase0/base structs, including `EpochProcessingSummary`
pub use base::{TotalBalances, ValidatorStatus, ValidatorStatuses};

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
