use crate::common::decrease_balance;
use safe_arith::SafeArith;
use types::{BeaconStateError as Error, *};

pub fn withdraw_balance<T: EthSpec>(
    state: &mut BeaconState<T>,
    validator_index: usize,
    amount: u64,
) -> Result<(), Error> {
    decrease_balance(state, validator_index as usize, amount)?;

    let withdrawal_address = Address::from_slice(
        &state
            .get_validator(validator_index)?
            .withdrawal_credentials
            .as_bytes()[12..],
    );
    let withdrawal = Withdrawal {
        index: *state.next_withdrawal_index()?,
        validator_index: validator_index as u64,
        address: withdrawal_address,
        amount,
    };
    state.next_withdrawal_index_mut()?.safe_add_assign(1)?;
    state.withdrawal_queue_mut()?.push(withdrawal)?;

    Ok(())
}
