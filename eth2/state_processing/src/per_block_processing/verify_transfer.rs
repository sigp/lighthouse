use super::errors::{BlockOperationError, TransferInvalid as Invalid};
use crate::per_block_processing::signature_sets::transfer_signature_set;
use crate::per_block_processing::VerifySignatures;
use bls::get_withdrawal_credentials;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Indicates if a `Transfer` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Transfer` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.8.0
pub fn verify_transfer<T: EthSpec>(
    state: &BeaconState<T>,
    transfer: &Transfer,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    verify_transfer_parametric(state, transfer, verify_signatures, spec, false)
}

/// Like `verify_transfer` but doesn't run checks which may become true in future states.
///
/// Spec v0.8.0
pub fn verify_transfer_time_independent_only<T: EthSpec>(
    state: &BeaconState<T>,
    transfer: &Transfer,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    verify_transfer_parametric(state, transfer, verify_signatures, spec, true)
}

/// Parametric version of `verify_transfer` that allows some checks to be skipped.
///
/// When `time_independent_only == true`, time-specific parameters are ignored, including:
///
/// - Balance considerations (e.g., adequate balance, not dust, etc).
/// - `transfer.slot` does not have to exactly match `state.slot`, it just needs to be in the
///     present or future.
/// - Validator transfer eligibility (e.g., is withdrawable)
///
/// Spec v0.8.0
fn verify_transfer_parametric<T: EthSpec>(
    state: &BeaconState<T>,
    transfer: &Transfer,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
    time_independent_only: bool,
) -> Result<()> {
    let sender_balance = *state
        .balances
        .get(transfer.sender as usize)
        .ok_or_else(|| error(Invalid::FromValidatorUnknown(transfer.sender)))?;

    let recipient_balance = *state
        .balances
        .get(transfer.recipient as usize)
        .ok_or_else(|| error(Invalid::FromValidatorUnknown(transfer.recipient)))?;

    // Safely determine `amount + fee`.
    let total_amount = transfer
        .amount
        .checked_add(transfer.fee)
        .ok_or_else(|| error(Invalid::FeeOverflow(transfer.amount, transfer.fee)))?;

    // Verify the sender has adequate balance.
    verify!(
        time_independent_only || sender_balance >= total_amount,
        Invalid::FromBalanceInsufficient(total_amount, sender_balance)
    );

    // Verify sender balance will not be "dust" (i.e., greater than zero but less than the minimum deposit
    // amount).
    verify!(
        time_independent_only
            || (sender_balance == total_amount)
            || (sender_balance >= (total_amount + spec.min_deposit_amount)),
        Invalid::SenderDust(sender_balance - total_amount, spec.min_deposit_amount)
    );

    // Verify the recipient balance will not be dust.
    verify!(
        time_independent_only || ((recipient_balance + transfer.amount) >= spec.min_deposit_amount),
        Invalid::RecipientDust(sender_balance - total_amount, spec.min_deposit_amount)
    );

    // If loosely enforcing `transfer.slot`, ensure the slot is not in the past. Otherwise, ensure
    // the transfer slot equals the state slot.
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

    // Load the sender `Validator` record from the state.
    let sender_validator = state
        .validators
        .get(transfer.sender as usize)
        .ok_or_else(|| error(Invalid::FromValidatorUnknown(transfer.sender)))?;

    // Ensure one of the following is met:
    //
    // - Time dependent checks are being ignored.
    // - The sender has never been eligible for activation.
    // - The sender is withdrawable at the state's epoch.
    // - The transfer will not reduce the sender below the max effective balance.
    verify!(
        time_independent_only
            || sender_validator.activation_eligibility_epoch == spec.far_future_epoch
            || sender_validator.is_withdrawable_at(state.current_epoch())
            || total_amount + spec.max_effective_balance <= sender_balance,
        Invalid::FromValidatorIneligibleForTransfer(transfer.sender)
    );

    // Ensure the withdrawal credentials generated from the sender's pubkey match those stored in
    // the validator registry.
    //
    // This ensures the validator can only perform a transfer when they are in control of the
    // withdrawal address.
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

    if verify_signatures.is_true() {
        verify!(
            transfer_signature_set(state, transfer, spec)?.is_valid(),
            Invalid::BadSignature
        );
    }

    Ok(())
}

/// Executes a transfer on the state.
///
/// Does not check that the transfer is valid, however checks for overflow in all actions.
///
/// Spec v0.8.0
pub fn execute_transfer<T: EthSpec>(
    state: &mut BeaconState<T>,
    transfer: &Transfer,
    spec: &ChainSpec,
) -> Result<()> {
    let sender_balance = *state
        .balances
        .get(transfer.sender as usize)
        .ok_or_else(|| error(Invalid::FromValidatorUnknown(transfer.sender)))?;
    let recipient_balance = *state
        .balances
        .get(transfer.recipient as usize)
        .ok_or_else(|| error(Invalid::ToValidatorUnknown(transfer.recipient)))?;

    let proposer_index =
        state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)?;
    let proposer_balance = state.balances[proposer_index];

    let total_amount = transfer
        .amount
        .checked_add(transfer.fee)
        .ok_or_else(|| error(Invalid::FeeOverflow(transfer.amount, transfer.fee)))?;

    state.balances[transfer.sender as usize] =
        sender_balance.checked_sub(total_amount).ok_or_else(|| {
            error(Invalid::FromBalanceInsufficient(
                total_amount,
                sender_balance,
            ))
        })?;

    state.balances[transfer.recipient as usize] = recipient_balance
        .checked_add(transfer.amount)
        .ok_or_else(|| {
            error(Invalid::ToBalanceOverflow(
                recipient_balance,
                transfer.amount,
            ))
        })?;

    state.balances[proposer_index] =
        proposer_balance.checked_add(transfer.fee).ok_or_else(|| {
            error(Invalid::ProposerBalanceOverflow(
                proposer_balance,
                transfer.fee,
            ))
        })?;

    Ok(())
}
