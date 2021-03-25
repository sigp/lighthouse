use crate::per_epoch_processing::Error;
use safe_arith::SafeArith;
use tree_hash::TreeHash;
use types::{BeaconState, ChainSpec, EthSpec, Unsigned, VariableList};

/// Finish up an epoch update.
pub fn process_final_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch()?;

    // Reset eth1 data votes.
    if state
        .slot()
        .safe_add(1)?
        .safe_rem(T::SlotsPerEth1VotingPeriod::to_u64())?
        == 0
    {
        *state.eth1_data_votes_mut() = VariableList::empty();
    }

    // Update effective balances with hysteresis (lag).
    let hysteresis_increment = spec
        .effective_balance_increment
        .safe_div(spec.hysteresis_quotient)?;
    let downward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_downward_multiplier)?;
    let upward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_upward_multiplier)?;
    let (validators, balances) = state.validators_and_balances_mut();
    for (index, validator) in validators.iter_mut().enumerate() {
        let balance = balances[index];

        if balance.safe_add(downward_threshold)? < validator.effective_balance
            || validator.effective_balance.safe_add(upward_threshold)? < balance
        {
            validator.effective_balance = std::cmp::min(
                balance.safe_sub(balance.safe_rem(spec.effective_balance_increment)?)?,
                spec.max_effective_balance,
            );
        }
    }


    // Set historical root accumulator
    if next_epoch
        .as_u64()
        .safe_rem(T::SlotsPerHistoricalRoot::to_u64().safe_div(T::slots_per_epoch())?)?
        == 0
    {
        let historical_batch = state.historical_batch();
        state
            .historical_roots_mut()
            .push(historical_batch.tree_hash_root())?;
    }

    // Rotate current/previous epoch attestations
    let base_state = state.as_base_mut()?;
    base_state.previous_epoch_attestations =
        std::mem::take(&mut base_state.current_epoch_attestations);

    Ok(())
}
