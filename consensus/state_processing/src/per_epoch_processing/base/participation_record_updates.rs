use crate::EpochProcessingError;
use types::core::EthSpec;
use types::state::BeaconState;

pub fn process_participation_record_updates<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    let base_state = state.as_base_mut()?;
    base_state.previous_epoch_attestations =
        std::mem::take(&mut base_state.current_epoch_attestations);
    Ok(())
}
