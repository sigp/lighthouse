use crate::EpochProcessingError;
use core::result::Result;
use core::result::Result::Ok;
use types::beacon_state::BeaconState;
use types::eth_spec::EthSpec;
use types::participation_flags::ParticipationFlags;
use types::VariableList;

pub fn process_participation_flag_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
) -> Result<(), EpochProcessingError> {
    *state.previous_epoch_participation_mut()? =
        std::mem::take(state.current_epoch_participation_mut()?);
    *state.current_epoch_participation_mut()? = VariableList::new(vec![
        ParticipationFlags::default(
        );
        state.validators().len()
    ])?;
    Ok(())
}
