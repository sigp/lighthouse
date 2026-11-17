use super::errors::{BlockOperationError, ExitInvalid};
use crate::per_block_processing::{
    VerifySignatures,
    signature_sets::{exit_signature_set, get_pubkey_from_state},
};
use safe_arith::SafeArith;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<ExitInvalid>>;

fn error(reason: ExitInvalid) -> BlockOperationError<ExitInvalid> {
    BlockOperationError::invalid(reason)
}

/// Indicates if an `Exit` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Exit` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.12.1
pub fn verify_exit<E: EthSpec>(
    state: &BeaconState<E>,
    current_epoch: Option<Epoch>,
    signed_exit: &SignedVoluntaryExit,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let current_epoch = current_epoch.unwrap_or(state.current_epoch());
    let exit = &signed_exit.message;

    verify_exit_validator_checks(
        state.validators().get(exit.validator_index as usize),
        exit,
        current_epoch,
        spec.far_future_epoch,
        spec.shard_committee_period,
    )?;

    if verify_signatures.is_true() {
        verify!(
            exit_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                signed_exit,
                spec
            )?
            .verify(),
            ExitInvalid::BadSignature
        );
    }

    // [New in Electra:EIP7251]
    // Only exit validator if it has no pending withdrawals in the queue
    verify_exit_pending_balance(
        exit.validator_index,
        state
            .get_pending_balance_to_withdraw(exit.validator_index as usize)
            .ok(),
    )
}

/// The checks of `verify_exit` that read only the exiting validator's record.
///
/// Free of `EthSpec` so that it can be extracted with Aeneas and proved correct in Lean (see
/// `verification/operation_pool`).
pub fn verify_exit_validator_checks(
    validator: Option<&Validator>,
    exit: &VoluntaryExit,
    current_epoch: Epoch,
    far_future_epoch: Epoch,
    shard_committee_period: u64,
) -> Result<()> {
    let Some(validator) = validator else {
        return Err(error(ExitInvalid::ValidatorUnknown(exit.validator_index)));
    };

    // Verify the validator is active.
    verify!(
        validator.is_active_at(current_epoch),
        ExitInvalid::NotActive(exit.validator_index)
    );

    // Verify that the validator has not yet exited.
    verify!(
        validator.exit_epoch == far_future_epoch,
        ExitInvalid::AlreadyExited(exit.validator_index)
    );

    // Exits must specify an epoch when they become valid; they are not valid before then.
    verify!(
        current_epoch >= exit.epoch,
        ExitInvalid::FutureEpoch {
            state: current_epoch,
            exit: exit.epoch
        }
    );

    // Verify the validator has been active long enough.
    let earliest_exit_epoch = validator
        .activation_epoch
        .safe_add(shard_committee_period)?;
    verify!(
        current_epoch >= earliest_exit_epoch,
        ExitInvalid::TooYoungToExit {
            current_epoch,
            earliest_exit_epoch,
        }
    );

    Ok(())
}

/// The pending-withdrawal check of `verify_exit`.
///
/// `pending_balance_to_withdraw` is `None` when the state has no pending partial withdrawals
/// (before Electra) or when their sum could not be computed, in which case the check is skipped.
///
/// Free of `EthSpec` so that it can be extracted with Aeneas and proved correct in Lean (see
/// `verification/operation_pool`).
pub fn verify_exit_pending_balance(
    validator_index: u64,
    pending_balance_to_withdraw: Option<u64>,
) -> Result<()> {
    if let Some(pending_balance_to_withdraw) = pending_balance_to_withdraw {
        verify!(
            pending_balance_to_withdraw == 0,
            ExitInvalid::PendingWithdrawalInQueue(validator_index)
        );
    }

    Ok(())
}
