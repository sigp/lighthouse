use crate::per_epoch_processing::{
    single_pass::{process_epoch_single_pass, SinglePassConfig},
    Error,
};
use types::consts::altair::PARTICIPATION_FLAG_WEIGHTS;
use types::{BeaconState, ChainSpec, EthSpec};

/// Apply attester and proposer rewards.
///
/// This function should only be used for testing.
pub fn process_rewards_and_penalties_slow<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    process_epoch_single_pass(
        state,
        spec,
        SinglePassConfig {
            rewards_and_penalties: true,
            ..SinglePassConfig::disable_all()
        },
    )?;
    Ok(())
}

/// Get the weight for a `flag_index` from the constant list of all weights.
pub fn get_flag_weight(flag_index: usize) -> Result<u64, Error> {
    PARTICIPATION_FLAG_WEIGHTS
        .get(flag_index)
        .copied()
        .ok_or(Error::InvalidFlagIndex(flag_index))
}
