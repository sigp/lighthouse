//! The `AttestationGate` allows blocking attestation creation whilst a new head block is imported.
//!
//! This helps prevent the scenario where a block is received and verified before the attestation
//! deadline, but lack of system resources (e.g., disk IO) prevents that block being fully imported
//! (i.e., put in the DB) and set as head before the attestation deadline expires.
//!
//! ## Incentives
//!
//! Using the `ApplicationGate` means that low-resourced notes will attest late rather than
//! attesting wrong. Whilst this doesn't strictly follow the "honest validator guide", it's also
//! arguably not a blatant violation of it. Given a physically-bounded computer, there's always the
//! potential for delays whilst a node is processing information.
//!
//! This behaviour also falls well within the incentives of the Beacon Chain rewards/penalties
//! system. We will only consider Altair, since it is soon to be the only rewards system that
//! matters.
//!
//! This blocking behaviour deals with achieving the `TIMELY_HEAD_FLAG_INDEX` reward. It is awarded
//! based on this logic:
//!
//! ```ignore
//! MIN_ATTESTATION_INCLUSION_DELAY = 1
//! if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
//!     participation_flag_indices.append(TIMELY_HEAD_FLAG_INDEX)
//! ```
//!
//! If we consider the scenario where we attest to a block that we *know* is not the head, then
//! we're certainly going to miss the timely head reward. If we decide to wait until that block is
//! imported, then we risk getting an inclusion delay > 1. It's clear that in the former case we
//! have *no* chance of getting the reward whilst we have *some* chance in the later.
//!
//! There is of course the scenario where our inclusion delay becomes so great that we start to miss
//! the other "timely" flags. We mitigate this by applying the `ATTESTATION_BLOCKING_TIMEOUT` to
//! ensure we don't start attesting *so* late that we risk losing more rewards or jeopardising
//! finality.

use crate::metrics;
use parking_lot::{Condvar, Mutex};
use slog::{debug, warn, Logger};
use std::time::Duration;

const ATTESTATION_BLOCKING_TIMEOUT: Duration = Duration::from_millis(1_500);

pub struct AttestationGate {
    mutex: Mutex<bool>,
    condvar: Condvar,
    log: Logger,
}

impl AttestationGate {
    pub fn new(log: Logger) -> Self {
        Self {
            mutex: Mutex::new(false),
            condvar: Condvar::new(),
            log,
        }
    }

    pub fn prevent_attestation(&self) {
        *self.mutex.lock() = false;
    }

    pub fn allow_attestation(&self) {
        *self.mutex.lock() = true;
        let unblocked = self.condvar.notify_all();

        metrics::inc_counter_by(
            &metrics::BEACON_ATTESTATION_GATE_UNBLOCKED_TOTAL,
            unblocked as u64,
        );
        if unblocked > 0 {
            debug!(
                self.log,
                "Attestation gate unblocked threads";
                "count" => unblocked
            );
        }
    }

    pub fn block_until_attestation_permitted(&self) {
        let mut ready = self.mutex.lock();
        if !*ready {
            if self
                .condvar
                .wait_for(&mut ready, ATTESTATION_BLOCKING_TIMEOUT)
                .timed_out()
            {
                warn!(
                    self.log,
                    "Attestation gate timed out";
                    "timeout" => ?ATTESTATION_BLOCKING_TIMEOUT
                );
                metrics::inc_counter(&metrics::BEACON_ATTESTATION_GATE_TIMED_OUT_TOTAL);
            }
        }
    }
}
