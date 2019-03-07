use super::errors::{TransferInvalid as Invalid, TransferValidationError as Error};
use bls::get_withdrawal_credentials;
use ssz::SignedRoot;
use types::*;

/// Indicates if a `Transfer` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Transfer` is valid, otherwise indicates the reason for invalidity.
///
/// Note: this function is incomplete.
///
/// Spec v0.4.0
pub fn verify_transfer(
    state: &BeaconState,
    transfer: &Transfer,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let from_balance = *state
        .validator_balances
        .get(transfer.from as usize)
        .ok_or_else(|| Error::Invalid(Invalid::FromValidatorUnknown(transfer.from)))?;

    let total_amount = transfer
        .amount
        .checked_add(transfer.fee)
        .ok_or_else(|| Error::Invalid(Invalid::FeeOverflow(transfer.amount, transfer.fee)))?;

    verify!(
        from_balance >= transfer.amount,
        Invalid::FromBalanceInsufficient(transfer.amount, from_balance)
    );

    verify!(
        from_balance >= transfer.fee,
        Invalid::FromBalanceInsufficient(transfer.fee, from_balance)
    );

    verify!(
        (from_balance == total_amount)
            || (from_balance >= (total_amount + spec.min_deposit_amount)),
        Invalid::InvalidResultingFromBalance(from_balance - total_amount, spec.min_deposit_amount)
    );

    verify!(
        state.slot == transfer.slot,
        Invalid::StateSlotMismatch(state.slot, transfer.slot)
    );

    let from_validator = state
        .validator_registry
        .get(transfer.from as usize)
        .ok_or_else(|| Error::Invalid(Invalid::FromValidatorUnknown(transfer.from)))?;
    let epoch = state.slot.epoch(spec.slots_per_epoch);

    verify!(
        from_validator.is_withdrawable_at(epoch)
            || from_validator.activation_epoch == spec.far_future_epoch,
        Invalid::FromValidatorIneligableForTransfer(transfer.from)
    );

    let transfer_withdrawal_credentials = Hash256::from_slice(
        &get_withdrawal_credentials(&transfer.pubkey, spec.bls_withdrawal_prefix_byte)[..],
    );
    verify!(
        from_validator.withdrawal_credentials == transfer_withdrawal_credentials,
        Invalid::WithdrawalCredentialsMismatch
    );

    let message = transfer.signed_root();
    let domain = spec.get_domain(
        transfer.slot.epoch(spec.slots_per_epoch),
        Domain::Transfer,
        &state.fork,
    );

    verify!(
        transfer
            .signature
            .verify(&message[..], domain, &transfer.pubkey),
        Invalid::BadSignature
    );

    Ok(())
}

/// Executes a transfer on the state.
///
/// Does not check that the transfer is valid, however checks for overflow in all actions.
///
/// Spec v0.4.0
pub fn execute_transfer(
    state: &mut BeaconState,
    transfer: &Transfer,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let from_balance = *state
        .validator_balances
        .get(transfer.from as usize)
        .ok_or_else(|| Error::Invalid(Invalid::FromValidatorUnknown(transfer.from)))?;
    let to_balance = *state
        .validator_balances
        .get(transfer.to as usize)
        .ok_or_else(|| Error::Invalid(Invalid::ToValidatorUnknown(transfer.to)))?;

    let proposer_index = state.get_beacon_proposer_index(state.slot, spec)?;
    let proposer_balance = state.validator_balances[proposer_index];

    let total_amount = transfer
        .amount
        .checked_add(transfer.fee)
        .ok_or_else(|| Error::Invalid(Invalid::FeeOverflow(transfer.amount, transfer.fee)))?;

    state.validator_balances[transfer.from as usize] =
        from_balance.checked_sub(total_amount).ok_or_else(|| {
            Error::Invalid(Invalid::FromBalanceInsufficient(total_amount, from_balance))
        })?;

    state.validator_balances[transfer.to as usize] = to_balance
        .checked_add(transfer.amount)
        .ok_or_else(|| Error::Invalid(Invalid::ToBalanceOverflow(to_balance, transfer.amount)))?;

    state.validator_balances[proposer_index] =
        proposer_balance.checked_add(transfer.fee).ok_or_else(|| {
            Error::Invalid(Invalid::ProposerBalanceOverflow(
                proposer_balance,
                transfer.fee,
            ))
        })?;

    Ok(())
}
