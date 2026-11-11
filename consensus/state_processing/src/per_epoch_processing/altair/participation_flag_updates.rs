use crate::EpochProcessingError;
use types::core::EthSpec;
use types::state::BeaconState;

pub fn process_participation_flag_updates<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    state.rotate_participation_flags()?;
    Ok(())
}
