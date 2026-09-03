//! The builder pending-payment window.
//!
//! `builder_pending_payments` is a two-epoch sliding window of `2 * SLOTS_PER_EPOCH` entries.
//! The window consists of the previous epoch and the current epoch. At every epoch transition
//! window shifts one epoch forward. Bids are accepted in the current epoch, and are paid out
//! in the next epoch if they reach quorum. A payment is cleared in one of three ways:
//!
//! - **paid on reveal** (`apply_parent_execution_payload`): the child block revealed the parent's
//!   payload, so the withdrawal is queued in `builder_pending_withdrawals` and the slot is
//!   overwritten with `PendingPayment::default()`.
//! - **paid at epoch transition** (`process_builder_pending_payments`, epoch transition):
//!   the previous epoch is scanned and any payment with `weight >= quorum` has its withdrawal
//!   queued. the shift then discards the first half.
//! - **discarded payments**: the previous epoch is scanned for payments that never reached quorum
//!   and were never paid on reveal. Nothing is queued.
//!
//! No double payment means a payment is either paid on reveal or paid at the epoch transition.
//!
//! Today the logic is spread across three files, each computing the window index for itself:
//! - `per_block_processing.rs` (bid recording, pay on reveal)
//! - `process_operations.rs` (attestation weight accrual)
//! - `per_epoch_processing/single_pass.rs` (epoch transition)

pub mod adapter;
#[cfg(test)]
mod diff_tests;

/// Failures the real code surfaces as `BlockProcessingError` / `BeaconStateError` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// An index outside the window, or a window of the wrong length.
    Bounds,
    /// Arithmetic overflow, or `slots_per_epoch == 0`.
    Arith,
}

/// Matches `BuilderPendingWithdrawal` field for field, with `Address` flattened to `[u8; 20]`
/// so Aeneas can translate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingWithdrawal {
    pub fee_recipient: [u8; 20],
    pub amount: u64,
    pub builder_index: u64,
}

/// One slot of the builder payment window. Matches `BuilderPendingPayment` field for field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingPayment {
    pub weight: u64,
    pub withdrawal: PendingWithdrawal,
    pub proposer_index: u64,
}

/// Which epoch a payment belongs to, the previous or current epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentEpoch {
    /// The previous epoch: the first `SLOTS_PER_EPOCH` entries.
    Previous,
    /// The current epoch: the last `SLOTS_PER_EPOCH` entries.
    Current,
}

/// Index into the window of the payment for `slot`.
pub fn payment_index(
    slot: u64,
    slots_per_epoch: u64,
    epoch: PaymentEpoch,
) -> Result<u64, WindowError> {
    let slot_mod = slot
        .checked_rem(slots_per_epoch)
        .ok_or(WindowError::Arith)?;
    match epoch {
        PaymentEpoch::Current => slots_per_epoch
            .checked_add(slot_mod)
            .ok_or(WindowError::Arith),
        PaymentEpoch::Previous => Ok(slot_mod),
    }
}

/// Records the payment for a newly accepted bid.
pub fn record_bid_payment(
    payments: &mut [PendingPayment],
    slots_per_epoch: u64,
    slot: u64,
    withdrawal: PendingWithdrawal,
    proposer_index: u64,
) -> Result<(), WindowError> {
    if withdrawal.amount > 0 {
        let index = payment_index(slot, slots_per_epoch, PaymentEpoch::Current)? as usize;
        match payments.get_mut(index) {
            Some(entry) => {
                *entry = PendingPayment {
                    weight: 0,
                    withdrawal,
                    proposer_index,
                };
            }
            None => return Err(WindowError::Bounds),
        }
    }
    Ok(())
}

/// Adds an attester's effective balance to the weight of the payment at `index`.
pub fn add_attestation_weight(
    payments: &mut [PendingPayment],
    index: usize,
    effective_balance: u64,
) -> Result<(), WindowError> {
    match payments.get_mut(index) {
        Some(entry) => match entry.weight.checked_add(effective_balance) {
            Some(weight) => {
                entry.weight = weight;
                Ok(())
            }
            None => Err(WindowError::Arith),
        },
        None => Err(WindowError::Bounds),
    }
}

/// Pays the payment at `index`, because the child block revealed the parent's payload.
///
/// Queues its withdrawal if the amount is non-zero and clears the entry to all zeros. Returns
/// whether a withdrawal was queued. (`settle_builder_payment` in the real code.)
///
/// Clearing the entry is what prevents a double payment. A zero `weight` can never reach quorum,
/// so the epoch transition will not pay this entry again.
pub fn pay_on_reveal(
    payments: &mut [PendingPayment],
    withdrawals: &mut Vec<PendingWithdrawal>,
    index: usize,
) -> Result<bool, WindowError> {
    let withdrawal = match payments.get_mut(index) {
        Some(entry) => {
            let withdrawal = entry.withdrawal;
            *entry = PendingPayment::default();
            withdrawal
        }
        None => return Err(WindowError::Bounds),
    };

    let mut queued = false;
    if withdrawal.amount > 0 {
        withdrawals.push(withdrawal);
        queued = true;
    }
    Ok(queued)
}

/// Pays every previous-epoch payment that reached `quorum`, then shifts the window forward one
/// epoch.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub fn pay_at_epoch_transition(
    payments: &mut [PendingPayment],
    withdrawals: &mut Vec<PendingWithdrawal>,
    slots_per_epoch: u64,
    quorum: u64,
) -> Result<(), WindowError> {
    let spe = slots_per_epoch as usize;
    let len = spe.checked_mul(2).ok_or(WindowError::Arith)?;
    if payments.len() != len {
        return Err(WindowError::Bounds);
    }

    // Pay out the previous epoch.
    let mut i = 0;
    while i < spe {
        if payments[i].weight >= quorum {
            withdrawals.push(payments[i].withdrawal);
        }
        i += 1;
    }

    // Shift builder payment window up one epoch.
    let mut i = 0;
    while i < spe {
        payments[i] = payments[i + spe];
        i += 1;
    }

    // Clear the new current epoch portion of the builder payment window.
    let mut i = spe;
    while i < len {
        payments[i] = PendingPayment::default();
        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPE: u64 = 4;

    fn window() -> Vec<PendingPayment> {
        vec![PendingPayment::default(); 2 * SPE as usize]
    }

    fn withdrawal(amount: u64) -> PendingWithdrawal {
        PendingWithdrawal {
            fee_recipient: [7; 20],
            amount,
            builder_index: 3,
        }
    }

    fn index(slot: u64, epoch: PaymentEpoch) -> usize {
        payment_index(slot, SPE, epoch).unwrap() as usize
    }

    /// Bid, then pay on reveal: one withdrawal, and the following epoch pass must not pay it again.
    #[test]
    fn pay_on_reveal_then_quorum_pays_once() {
        let mut payments = window();
        let mut withdrawals = Vec::new();

        record_bid_payment(&mut payments, SPE, 5, withdrawal(100), 9).unwrap();
        add_attestation_weight(&mut payments, index(5, PaymentEpoch::Current), 1_000).unwrap();

        assert!(
            pay_on_reveal(
                &mut payments,
                &mut withdrawals,
                index(5, PaymentEpoch::Current)
            )
            .unwrap()
        );
        assert_eq!(withdrawals, vec![withdrawal(100)]);

        // Whatever the quorum, a slot paid on reveal has weight 0 and is not paid again.
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 1).unwrap();
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 1).unwrap();
        assert_eq!(withdrawals, vec![withdrawal(100)]);
    }

    /// Bid, reach quorum, no reveal: paid exactly once by the epoch pass, then evicted.
    #[test]
    fn quorum_without_reveal_pays_once() {
        let mut payments = window();
        let mut withdrawals = Vec::new();

        record_bid_payment(&mut payments, SPE, 5, withdrawal(100), 9).unwrap();
        add_attestation_weight(&mut payments, index(5, PaymentEpoch::Current), 1_000).unwrap();

        // First transition moves it to the previous half; second pays it.
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 500).unwrap();
        assert!(withdrawals.is_empty());
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 500).unwrap();
        assert_eq!(withdrawals, vec![withdrawal(100)]);
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 500).unwrap();
        assert_eq!(withdrawals, vec![withdrawal(100)]);
    }

    /// Below quorum and never paid on reveal: evicted unpaid.
    #[test]
    fn below_quorum_is_evicted_unpaid() {
        let mut payments = window();
        let mut withdrawals = Vec::new();

        record_bid_payment(&mut payments, SPE, 5, withdrawal(100), 9).unwrap();
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 500).unwrap();
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 500).unwrap();
        assert!(withdrawals.is_empty());
        assert!(payments.iter().all(|p| *p == PendingPayment::default()));
    }

    /// With `quorum == 0`, empty entries queue zero-amount withdrawals, as in the spec. The
    /// no-double-payment theorem is stated over non-zero withdrawals because of this.
    #[test]
    fn zero_quorum_queues_zero_amount_withdrawals() {
        let mut payments = window();
        let mut withdrawals = Vec::new();

        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 0).unwrap();
        assert_eq!(withdrawals.len(), SPE as usize);
        assert!(withdrawals.iter().all(|w| w.amount == 0));
    }

    /// After an epoch transition, a previous-epoch bid has moved to current epoch portion of the builder payment window.
    /// `pay_on_reveal` must find it there using `PaymentEpoch::Previous`.
    #[test]
    fn pay_on_reveal_index_follows_the_shift() {
        let mut payments = window();
        let mut withdrawals = Vec::new();

        record_bid_payment(&mut payments, SPE, 6, withdrawal(100), 9).unwrap();
        pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, u64::MAX).unwrap();

        assert_eq!(
            payments[index(6, PaymentEpoch::Previous)].withdrawal,
            withdrawal(100)
        );
        assert!(
            pay_on_reveal(
                &mut payments,
                &mut withdrawals,
                index(6, PaymentEpoch::Previous)
            )
            .unwrap()
        );
        assert_eq!(withdrawals, vec![withdrawal(100)]);
    }

    /// A window of the wrong length is refused before any loop runs.
    #[test]
    fn wrong_length_window_is_refused() {
        let mut payments = vec![PendingPayment::default(); 3];
        let mut withdrawals = Vec::new();
        assert_eq!(
            pay_at_epoch_transition(&mut payments, &mut withdrawals, SPE, 0),
            Err(WindowError::Bounds)
        );
        assert!(withdrawals.is_empty());
    }
}
