use crate::{common::increase_balance, EpochProcessingError};
use safe_arith::SafeArith;
use types::{BeaconState, ChainSpec, EthSpec};

pub fn process_pending_balance_deposits<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let available_for_processing = state
        .deposit_balance_to_consume()?
        .safe_add(state.get_activation_exit_churn_limit(spec)?)?;
    let mut processed_amount = 0;
    let mut next_deposit_index = 0;

    // move pending_balance_deposits to a mutable vector
    let mut pending_balance_deposits = Vec::from(std::mem::replace(
        state.pending_balance_deposits_mut()?,
        Vec::new().into(),
    ));

    for deposit in pending_balance_deposits.iter() {
        if processed_amount + deposit.amount > available_for_processing {
            break;
        }
        increase_balance(state, deposit.index as usize, deposit.amount)?;
        processed_amount += deposit.amount;
        next_deposit_index += 1;
    }
    pending_balance_deposits.drain(0..next_deposit_index);
    *state.pending_balance_deposits_mut()? = pending_balance_deposits.into();

    if state.pending_balance_deposits()?.len() == 0 {
        *state.deposit_balance_to_consume_mut()? = 0;
    } else {
        *state.deposit_balance_to_consume_mut()? = available_for_processing - processed_amount;
    }

    Ok(())
}
