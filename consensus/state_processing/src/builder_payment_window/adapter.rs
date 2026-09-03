//! The `BeaconState` side of the builder payment window.
//!
//! Every function here converts between the state's types (`Vector`, `ProgressiveList`,
//! `Address`) and the plain types the model uses, calls the model, and writes the result back.
//! No decisions are made here; that is the point. The proof covers the model, and this file is
//! kept small enough to check by reading.

use super::{self as model, PendingPayment, PendingWithdrawal, WindowError};
use crate::per_block_processing::errors::BlockProcessingError;
use crate::per_epoch_processing::errors::EpochProcessingError;
use milhouse::Vector;
use safe_arith::ArithError;
use types::{
    Address, BeaconState, BeaconStateError, BuilderPendingPayment, BuilderPendingWithdrawal,
    EthSpec, Slot,
};

pub fn to_model_withdrawal(w: &BuilderPendingWithdrawal) -> PendingWithdrawal {
    PendingWithdrawal {
        fee_recipient: w.fee_recipient.0.0,
        amount: w.amount,
        builder_index: w.builder_index,
    }
}

pub fn to_real_withdrawal(w: &PendingWithdrawal) -> BuilderPendingWithdrawal {
    BuilderPendingWithdrawal {
        fee_recipient: Address::from(w.fee_recipient),
        amount: w.amount,
        builder_index: w.builder_index,
    }
}

pub fn to_model_payment(p: &BuilderPendingPayment) -> PendingPayment {
    PendingPayment {
        weight: p.weight,
        withdrawal: to_model_withdrawal(&p.withdrawal),
        proposer_index: p.proposer_index,
    }
}

pub fn to_real_payment(p: &PendingPayment) -> BuilderPendingPayment {
    BuilderPendingPayment {
        weight: p.weight,
        withdrawal: to_real_withdrawal(&p.withdrawal),
        proposer_index: p.proposer_index,
    }
}

/// The whole window, in model form.
fn read_window<E: EthSpec>(
    state: &BeaconState<E>,
) -> Result<Vec<PendingPayment>, BeaconStateError> {
    Ok(state
        .builder_pending_payments()?
        .iter()
        .map(to_model_payment)
        .collect())
}

/// Replaces the whole window. Rebuilds the persistent `Vector`, so only for operations that
/// run once per block or once per epoch.
fn write_window<E: EthSpec>(
    state: &mut BeaconState<E>,
    payments: Vec<PendingPayment>,
) -> Result<(), BeaconStateError> {
    let real = payments.iter().map(to_real_payment).collect::<Vec<_>>();
    *state.builder_pending_payments_mut()? = Vector::new(real)?;
    Ok(())
}

fn queue_withdrawals<E: EthSpec>(
    state: &mut BeaconState<E>,
    withdrawals: Vec<PendingWithdrawal>,
) -> Result<(), BeaconStateError> {
    for withdrawal in withdrawals {
        state
            .builder_pending_withdrawals_mut()?
            .push(to_real_withdrawal(&withdrawal))?;
    }
    Ok(())
}

fn block_error(e: WindowError, index: usize) -> BlockProcessingError {
    match e {
        WindowError::Bounds => BlockProcessingError::BuilderPaymentIndexOutOfBounds(index),
        WindowError::Arith => BlockProcessingError::ArithError(ArithError::Overflow),
    }
}

/// Records the pending payment for a bid at `slot`. Zero-amount withdrawals are not recorded.
pub fn record_builder_pending_payment<E: EthSpec>(
    state: &mut BeaconState<E>,
    slot: Slot,
    withdrawal: BuilderPendingWithdrawal,
    proposer_index: u64,
) -> Result<(), BlockProcessingError> {
    let slots_per_epoch = E::slots_per_epoch();
    let index = model::payment_index(slot.as_u64(), slots_per_epoch, model::PaymentEpoch::Current)
        .map_err(|e| block_error(e, 0))? as usize;

    let mut payments = read_window(state)?;
    model::record_bid_payment(
        &mut payments,
        slots_per_epoch,
        slot.as_u64(),
        to_model_withdrawal(&withdrawal),
        proposer_index,
    )
    .map_err(|e| match e {
        WindowError::Bounds => BlockProcessingError::BeaconStateError(
            BeaconStateError::InvalidBuilderPendingPaymentsIndex(index),
        ),
        other => block_error(other, index),
    })?;
    write_window(state, payments)?;
    Ok(())
}

/// Adds an attester's effective balance to the weight of the pending payment at
/// `payment_index`. Whether the attestation counts at all is decided by the caller.
///
/// Called once per attestation, so this touches the single entry rather than rebuilding the
/// window.
pub fn add_builder_payment_weight<E: EthSpec>(
    state: &mut BeaconState<E>,
    payment_index: usize,
    effective_balance: u64,
) -> Result<(), BlockProcessingError> {
    let entry = state
        .builder_pending_payments_mut()?
        .get_mut(payment_index)
        .ok_or(BlockProcessingError::BuilderPaymentIndexOutOfBounds(
            payment_index,
        ))?;

    let mut payment = to_model_payment(entry);
    model::add_attestation_weight(std::slice::from_mut(&mut payment), 0, effective_balance)
        .map_err(|e| block_error(e, payment_index))?;
    *entry = to_real_payment(&payment);
    Ok(())
}

/// Pays the pending payment at `payment_index`, because the child block revealed the parent's
/// payload: its withdrawal is queued (if non-zero) and the entry is cleared.
pub fn settle_builder_payment<E: EthSpec>(
    state: &mut BeaconState<E>,
    payment_index: usize,
) -> Result<(), BlockProcessingError> {
    let entry = state
        .builder_pending_payments_mut()?
        .get_mut(payment_index)
        .ok_or(BlockProcessingError::BuilderPaymentIndexOutOfBounds(
            payment_index,
        ))?;

    let mut payment = to_model_payment(entry);
    let mut withdrawals = Vec::new();
    model::pay_on_reveal(std::slice::from_mut(&mut payment), &mut withdrawals, 0)
        .map_err(|e| block_error(e, payment_index))?;
    *entry = to_real_payment(&payment);

    queue_withdrawals(state, withdrawals)?;
    Ok(())
}

/// Pays every previous-epoch pending payment whose weight reached `quorum`, then shifts the
/// window forward one epoch.
pub fn process_builder_pending_payments<E: EthSpec>(
    state: &mut BeaconState<E>,
    quorum: u64,
) -> Result<(), EpochProcessingError> {
    let mut payments = read_window(state)?;
    let len = payments.len();
    let mut withdrawals = Vec::new();
    model::pay_at_epoch_transition(
        &mut payments,
        &mut withdrawals,
        E::slots_per_epoch(),
        quorum,
    )
    .map_err(|e| match e {
        WindowError::Bounds => EpochProcessingError::BeaconStateError(
            BeaconStateError::InvalidBuilderPendingPaymentsIndex(len),
        ),
        WindowError::Arith => EpochProcessingError::ArithError(ArithError::Overflow),
    })?;
    write_window(state, payments)?;
    queue_withdrawals(state, withdrawals)?;
    Ok(())
}
