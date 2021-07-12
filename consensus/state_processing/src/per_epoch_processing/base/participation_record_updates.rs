use crate::EpochProcessingError;
use types::beacon_state::BeaconState;
use types::eth_spec::EthSpec;

pub fn process_participation_record_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
) -> Result<(), EpochProcessingError> {
    let base_state = state.as_base_mut()?;
    base_state.previous_epoch_attestations =
        std::mem::take(&mut base_state.current_epoch_attestations);
    Ok(())
}
