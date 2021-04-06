use crate::EpochProcessingError;
use core::result::Result;
use core::result::Result::Ok;
use types::beacon_state::BeaconState;
use types::eth_spec::EthSpec;
use types::participation_flags::ParticipationFlags;
use types::VariableList;

//TODO: there's no EF test for this one
pub fn process_participation_flag_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
) -> Result<(), EpochProcessingError> {
    let altair_state = state.as_altair_mut()?;
    altair_state.previous_epoch_participation =
        std::mem::take(&mut altair_state.current_epoch_participation);
    altair_state.current_epoch_participation =
        VariableList::new(vec![
            ParticipationFlags::default();
            altair_state.validators.len()
        ])?;
    Ok(())
}
