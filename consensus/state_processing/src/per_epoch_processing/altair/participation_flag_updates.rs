use crate::EpochProcessingError;
use milhouse::List;
use types::attestation::ParticipationFlags;
use types::core::EthSpec;
use types::state::BeaconState;

pub fn process_participation_flag_updates<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    *state.previous_epoch_participation_mut()? =
        std::mem::take(state.current_epoch_participation_mut()?);
    *state.current_epoch_participation_mut()? =
        List::repeat(ParticipationFlags::default(), state.validators().len())?;
    Ok(())
}
