use super::errors::EpochProcessingError;
use safe_arith::SafeArith;
use types::beacon_state::BeaconState;
use types::eth_spec::EthSpec;
use types::{List, Unsigned};

pub fn process_eth1_data_reset<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    if state
        .slot()
        .safe_add(1)?
        .safe_rem(E::SlotsPerEth1VotingPeriod::to_u64())?
        == 0
    {
        *state.eth1_data_votes_mut() = List::empty();
    }
    Ok(())
}

pub fn process_slashings_reset<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    let next_epoch = state.next_epoch()?;
    state.set_slashings(next_epoch, 0)?;
    Ok(())
}

pub fn process_randao_mixes_reset<E: EthSpec>(
    state: &mut BeaconState<E>,
) -> Result<(), EpochProcessingError> {
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch()?;
    state.set_randao_mix(next_epoch, *state.get_randao_mix(current_epoch)?)?;
    Ok(())
}
