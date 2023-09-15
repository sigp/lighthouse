//! Concurrency helpers for synchronising block proposal with fork choice.
//!
//! The transmitter provides a way for a thread runnning fork choice on a schedule to signal
//! to the receiver that fork choice has been updated for a given slot.
use crate::BeaconChainError;
use parking_lot::{Condvar, Mutex};
use std::sync::Arc;
use std::time::Duration;
use types::Slot;

/// Sender, for use by the per-slot task timer.
pub struct ForkChoiceSignalTx {
    pair: Arc<(Mutex<Slot>, Condvar)>,
}

/// Receiver, for use by the beacon chain waiting on fork choice to complete.
pub struct ForkChoiceSignalRx {
    pair: Arc<(Mutex<Slot>, Condvar)>,
}

pub enum ForkChoiceWaitResult {
    /// Successfully reached a slot greater than or equal to the awaited slot.
    Success(Slot),
    /// Fork choice was updated to a lower slot, indicative of lag or processing delays.
    Behind(Slot),
    /// Timed out waiting for the fork choice update from the sender.
    TimeOut,
}

impl ForkChoiceSignalTx {
    pub fn new() -> Self {
        let pair = Arc::new((Mutex::new(Slot::new(0)), Condvar::new()));
        Self { pair }
    }

    pub fn get_receiver(&self) -> ForkChoiceSignalRx {
        ForkChoiceSignalRx {
            pair: self.pair.clone(),
        }
    }

    /// Signal to the receiver that fork choice has been updated to `slot`.
    ///
    /// Return an error if the provided `slot` is strictly less than any previously provided slot.
    pub fn notify_fork_choice_complete(&self, slot: Slot) -> Result<(), BeaconChainError> {
        let (lock, condvar) = &*self.pair;

        let mut current_slot = lock.lock();

        if slot < *current_slot {
            return Err(BeaconChainError::ForkChoiceSignalOutOfOrder {
                current: *current_slot,
                latest: slot,
            });
        } else {
            *current_slot = slot;
        }

        // We use `notify_all` because there may be multiple block proposals waiting simultaneously.
        // Usually there'll be 0-1.
        condvar.notify_all();

        Ok(())
    }
}

impl Default for ForkChoiceSignalTx {
    fn default() -> Self {
        Self::new()
    }
}

impl ForkChoiceSignalRx {
    pub fn wait_for_fork_choice(&self, slot: Slot, timeout: Duration) -> ForkChoiceWaitResult {
        let (lock, condvar) = &*self.pair;

        let mut current_slot = lock.lock();

        // Wait for `current_slot >= slot`.
        //
        // Do not loop and wait, if we receive an update for the wrong slot then something is
        // quite out of whack and we shouldn't waste more time waiting.
        if *current_slot < slot {
            let timeout_result = condvar.wait_for(&mut current_slot, timeout);

            if timeout_result.timed_out() {
                return ForkChoiceWaitResult::TimeOut;
            }
        }

        if *current_slot >= slot {
            ForkChoiceWaitResult::Success(*current_slot)
        } else {
            ForkChoiceWaitResult::Behind(*current_slot)
        }
    }
}
