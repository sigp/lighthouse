use super::errors::EpochProcessingError;
use milhouse::List;
use safe_arith::SafeArith;
use types::Spec;
use types::state::BeaconState;

pub fn process_eth1_data_reset(state: &mut BeaconState) -> Result<(), EpochProcessingError> {
    if state
        .slot()
        .safe_add(1)?
        .safe_rem(Spec::SLOTS_PER_ETH1_VOTING_PERIOD as u64)?
        == 0
    {
        *state.eth1_data_votes_mut() = List::empty();
    }
    Ok(())
}

pub fn process_slashings_reset(state: &mut BeaconState) -> Result<(), EpochProcessingError> {
    let next_epoch = state.next_epoch()?;
    state.set_slashings(next_epoch, 0)?;
    Ok(())
}

pub fn process_randao_mixes_reset(state: &mut BeaconState) -> Result<(), EpochProcessingError> {
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch()?;
    state.set_randao_mix(next_epoch, *state.get_randao_mix(current_epoch)?)?;
    Ok(())
}
