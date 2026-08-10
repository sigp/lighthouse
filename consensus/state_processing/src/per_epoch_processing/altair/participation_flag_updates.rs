use crate::EpochProcessingError;
use types::state::BeaconState;

pub fn process_participation_flag_updates(
    state: &mut BeaconState,
) -> Result<(), EpochProcessingError> {
    state.rotate_participation_flags()?;
    Ok(())
}
