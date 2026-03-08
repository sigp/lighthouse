use crate::EpochProcessingError;
use crate::per_epoch_processing::single_pass::{SinglePassConfig, process_epoch_single_pass};
use types::core::{ChainSpec, EthSpec};
use types::state::BeaconState;

/// Slow version of `process_inactivity_updates` that runs a subset of single-pass processing.
///
/// Should not be used for block processing, but is useful for testing & analytics.
pub fn process_inactivity_updates_slow<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    process_epoch_single_pass(
        state,
        spec,
        SinglePassConfig {
            inactivity_updates: true,
            ..SinglePassConfig::disable_all()
        },
    )?;
    Ok(())
}
