use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

/// A simple wrapper around `parking_lot::RwLock` that only permits read/write access with a
/// time-out (i.e., no indefinitely-blocking operations).
pub struct TimeoutRwLock<T>(RwLock<T>);

impl<T> TimeoutRwLock<T> {
    pub fn new(inner: T) -> Self {
        Self(RwLock::new(inner))
    }

    pub fn try_read_for(&self, timeout: Duration) -> Option<RwLockReadGuard<T>> {
        self.0.try_read_for(timeout)
    }

    pub fn try_write_for(&self, timeout: Duration) -> Option<RwLockWriteGuard<T>> {
        self.0.try_write_for(timeout)
    }
}
