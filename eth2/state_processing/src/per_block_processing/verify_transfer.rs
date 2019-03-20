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
/// Spec v0.5.0
pub fn verify_transfer(
    state: &BeaconState,
    transfer: &Transfer,
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify_transfer_parametric(state, transfer, spec, false)
}

/// Like `verify_transfer` but doesn't run checks which may become true in future states.
pub fn verify_transfer_time_independent_only(
    state: &BeaconState,
    transfer: &Transfer,
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify_transfer_parametric(state, transfer, spec, true)
}

/// Parametric version of `verify_transfer` that allows some checks to be skipped.
fn verify_transfer_parametric(
    state: &BeaconState,
    transfer: &Transfer,
    spec: &ChainSpec,
    time_independent_only: bool,
) -> Result<(), Error> {
    let sender_balance = *state
        .validator_balances
        .get(transfer.sender as usize)
        .ok_or_else(|| Error::Invalid(Invalid::FromValidatorUnknown(transfer.sender)))?;

    let total_amount = transfer
        .amount
        .checked_add(transfer.fee)
        .ok_or_else(|| Error::Invalid(Invalid::FeeOverflow(transfer.amount, transfer.fee)))?;

    verify!(
        time_independent_only || sender_balance >= transfer.amount,
        Invalid::FromBalanceInsufficient(transfer.amount, sender_balance)
    );

    verify!(
        time_independent_only || sender_balance >= transfer.fee,
        Invalid::FromBalanceInsufficient(transfer.fee, sender_balance)
    );

    verify!(
        time_independent_only
            || (sender_balance == total_amount)
            || (sender_balance >= (total_amount + spec.min_deposit_amount)),
        Invalid::InvalidResultingFromBalance(
            sender_balance - total_amount,
            spec.min_deposit_amount
        )
    );

    if time_independent_only {
        verify!(
            state.slot <= transfer.slot,
            Invalid::TransferSlotInPast(state.slot, transfer.slot)
        );
    } else {
        verify!(
            state.slot == transfer.slot,
            Invalid::StateSlotMismatch(state.slot, transfer.slot)
        );
    }

    let sender_validator = state
        .validator_registry
        .get(transfer.sender as usize)
        .ok_or_else(|| Error::Invalid(Invalid::FromValidatorUnknown(transfer.sender)))?;
    let epoch = state.slot.epoch(spec.slots_per_epoch);

    verify!(
        time_independent_only
            || sender_validator.is_withdrawable_at(epoch)
            || sender_validator.activation_epoch == spec.far_future_epoch,
        Invalid::FromValidatorIneligableForTransfer(transfer.sender)
    );

    let transfer_withdrawal_credentials = Hash256::from_slice(
        &get_withdrawal_credentials(&transfer.pubkey, spec.bls_withdrawal_prefix_byte)[..],
    );
    verify!(
        sender_validator.withdrawal_credentials == transfer_withdrawal_credentials,
        Invalid::WithdrawalCredentialsMismatch(
            sender_validator.withdrawal_credentials,
            transfer_withdrawal_credentials
        )
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
/// Spec v0.5.0
pub fn execute_transfer(
    state: &mut BeaconState,
    transfer: &Transfer,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let sender_balance = *state
        .validator_balances
        .get(transfer.sender as usize)
        .ok_or_else(|| Error::Invalid(Invalid::FromValidatorUnknown(transfer.sender)))?;
    let recipient_balance = *state
        .validator_balances
        .get(transfer.recipient as usize)
        .ok_or_else(|| Error::Invalid(Invalid::ToValidatorUnknown(transfer.recipient)))?;

    let proposer_index =
        state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)?;
    let proposer_balance = state.validator_balances[proposer_index];

    let total_amount = transfer
        .amount
        .checked_add(transfer.fee)
        .ok_or_else(|| Error::Invalid(Invalid::FeeOverflow(transfer.amount, transfer.fee)))?;

    state.validator_balances[transfer.sender as usize] =
        sender_balance.checked_sub(total_amount).ok_or_else(|| {
            Error::Invalid(Invalid::FromBalanceInsufficient(
                total_amount,
                sender_balance,
            ))
        })?;

    state.validator_balances[transfer.recipient as usize] = recipient_balance
        .checked_add(transfer.amount)
        .ok_or_else(|| {
            Error::Invalid(Invalid::ToBalanceOverflow(
                recipient_balance,
                transfer.amount,
            ))
        })?;

    state.validator_balances[proposer_index] =
        proposer_balance.checked_add(transfer.fee).ok_or_else(|| {
            Error::Invalid(Invalid::ProposerBalanceOverflow(
                proposer_balance,
                transfer.fee,
            ))
        })?;

    Ok(())
}
