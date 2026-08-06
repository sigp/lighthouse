use crate::EpochProcessingError;
use types::state::BeaconState;

pub fn process_participation_record_updates(
    state: &mut BeaconState,
) -> Result<(), EpochProcessingError> {
    let base_state = state.as_base_mut()?;
    base_state.previous_epoch_attestations =
        std::mem::take(&mut base_state.current_epoch_attestations);
    Ok(())
}
