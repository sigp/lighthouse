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
