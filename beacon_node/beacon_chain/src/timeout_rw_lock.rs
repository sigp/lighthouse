use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// A simple wrapper around `parking_lot::RwLock` that only permits read/write access with a
/// time-out (i.e., no indefinitely-blocking operations).
///
/// Timeouts can be optionally disabled at runtime for all instances of this type by calling
/// `TimeoutRwLock::disable_timeouts()`.
pub struct TimeoutRwLock<T>(RwLock<T>);

const TIMEOUT_LOCKS_ENABLED_DEFAULT: bool = true;
static TIMEOUT_LOCKS_ENABLED: AtomicBool = AtomicBool::new(TIMEOUT_LOCKS_ENABLED_DEFAULT);

impl TimeoutRwLock<()> {
    pub fn disable_timeouts() {
        // Use the strongest `SeqCst` ordering for the write, as it should only happen once.
        TIMEOUT_LOCKS_ENABLED.store(false, Ordering::SeqCst);
    }
}

impl<T> TimeoutRwLock<T> {
    pub fn new(inner: T) -> Self {
        Self(RwLock::new(inner))
    }

    fn timeouts_enabled() -> bool {
        // Use relaxed ordering as it's OK for a few locks to run with timeouts "accidentally",
        // and we want the atomic check to be as fast as possible.
        TIMEOUT_LOCKS_ENABLED.load(Ordering::Relaxed)
    }

    pub fn try_read_for(&self, timeout: Duration) -> Option<RwLockReadGuard<T>> {
        if Self::timeouts_enabled() {
            self.0.try_read_for(timeout)
        } else {
            Some(self.0.read())
        }
    }

    pub fn try_write_for(&self, timeout: Duration) -> Option<RwLockWriteGuard<T>> {
        if Self::timeouts_enabled() {
            self.0.try_write_for(timeout)
        } else {
            Some(self.0.write())
        }
    }
}
