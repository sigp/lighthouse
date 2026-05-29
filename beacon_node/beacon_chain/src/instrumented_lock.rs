//! An instrumented `parking_lot::RwLock` wrapper.
//!
//! This is the reusable building block requested in issue #8147: instead of
//! manually instrumenting every call site that acquires a contended lock, the
//! lock itself measures contention. An [`InstrumentedRwLock`]:
//!
//! 1. records the time spent **acquiring** the lock (wait time),
//! 2. records the time the guard was **held** (hold time), and
//! 3. logs a backtrace whenever a guard is held for longer than a configured
//!    threshold, pointing directly at the release site.
//!
//! All instrumentation is transparent to callers: the returned guards
//! `Deref`/`DerefMut` to the protected value and the measurements happen in
//! their `Drop` implementations. The guards intentionally contain only
//! `Send + Sync` metadata, so they keep the same `Send`/`Sync` properties as
//! the underlying `parking_lot` guards.

use parking_lot::{RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard};
use std::backtrace::Backtrace;
use std::ops::{Deref, DerefMut};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ::metrics::{Histogram, Result as MetricsResult};

/// A lazily-initialised Prometheus histogram, matching the pattern used in
/// `beacon_chain::metrics`.
type LockMetric = LazyLock<MetricsResult<Histogram>>;

/// The histograms a single [`InstrumentedRwLock`] reports to.
///
/// `*_acquire` histograms measure the time spent waiting to obtain the lock;
/// `*_hold` histograms measure how long the guard stayed alive once acquired.
pub struct LockMetrics {
    pub read_acquire: &'static LockMetric,
    pub write_acquire: &'static LockMetric,
    pub upgradable_acquire: &'static LockMetric,
    pub read_hold: &'static LockMetric,
    pub write_hold: &'static LockMetric,
    pub upgradable_hold: &'static LockMetric,
}

fn observe(metric: &'static LockMetric, duration: Duration) {
    if let Ok(histogram) = &**metric {
        histogram.observe(duration.as_secs_f64());
    }
}

/// Record the hold time of a guard and, if it exceeds `threshold`, emit a
/// warning containing a backtrace of the release site.
fn record_hold(
    name: &'static str,
    mode: &'static str,
    acquired: Instant,
    threshold: Duration,
    hold_metric: &'static LockMetric,
) {
    let held = acquired.elapsed();
    observe(hold_metric, held);

    if held > threshold {
        tracing::warn!(
            lock = name,
            mode,
            held_ms = held.as_millis() as u64,
            threshold_ms = threshold.as_millis() as u64,
            backtrace = %Backtrace::force_capture(),
            "Lock held longer than threshold",
        );
    }
}

/// A `parking_lot::RwLock` that automatically instruments acquisition and hold
/// times. See the module-level documentation for details.
pub struct InstrumentedRwLock<T> {
    inner: RwLock<T>,
    metrics: &'static LockMetrics,
    name: &'static str,
    hold_threshold: Duration,
}

impl<T> InstrumentedRwLock<T> {
    pub fn new(
        value: T,
        metrics: &'static LockMetrics,
        name: &'static str,
        hold_threshold: Duration,
    ) -> Self {
        Self {
            inner: RwLock::new(value),
            metrics,
            name,
            hold_threshold,
        }
    }

    pub fn read(&self) -> InstrumentedRwLockReadGuard<'_, T> {
        let timer = ::metrics::start_timer(self.metrics.read_acquire);
        let guard = self.inner.read();
        ::metrics::stop_timer(timer);
        InstrumentedRwLockReadGuard {
            guard: Some(guard),
            metrics: self.metrics,
            name: self.name,
            hold_threshold: self.hold_threshold,
            acquired: Instant::now(),
        }
    }

    pub fn write(&self) -> InstrumentedRwLockWriteGuard<'_, T> {
        let timer = ::metrics::start_timer(self.metrics.write_acquire);
        let guard = self.inner.write();
        ::metrics::stop_timer(timer);
        InstrumentedRwLockWriteGuard {
            guard: Some(guard),
            metrics: self.metrics,
            name: self.name,
            hold_threshold: self.hold_threshold,
            acquired: Instant::now(),
        }
    }

    pub fn upgradable_read(&self) -> InstrumentedRwLockUpgradableReadGuard<'_, T> {
        let timer = ::metrics::start_timer(self.metrics.upgradable_acquire);
        let guard = self.inner.upgradable_read();
        ::metrics::stop_timer(timer);
        InstrumentedRwLockUpgradableReadGuard {
            guard: Some(guard),
            metrics: self.metrics,
            name: self.name,
            hold_threshold: self.hold_threshold,
            acquired: Instant::now(),
        }
    }
}

// ---- Read guard ----

pub struct InstrumentedRwLockReadGuard<'a, T> {
    guard: Option<RwLockReadGuard<'a, T>>,
    metrics: &'static LockMetrics,
    name: &'static str,
    hold_threshold: Duration,
    acquired: Instant,
}

impl<T> Deref for InstrumentedRwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().expect("guard is present until drop")
    }
}

impl<T> Drop for InstrumentedRwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            drop(guard);
            record_hold(
                self.name,
                "read",
                self.acquired,
                self.hold_threshold,
                self.metrics.read_hold,
            );
        }
    }
}

// ---- Write guard ----

pub struct InstrumentedRwLockWriteGuard<'a, T> {
    guard: Option<RwLockWriteGuard<'a, T>>,
    metrics: &'static LockMetrics,
    name: &'static str,
    hold_threshold: Duration,
    acquired: Instant,
}

impl<'a, T> InstrumentedRwLockWriteGuard<'a, T> {
    /// Atomically downgrade a write guard into a read guard, preserving
    /// instrumentation. The write-hold time is recorded at the point of
    /// downgrade and a fresh read-hold measurement begins.
    pub fn downgrade(mut s: Self) -> InstrumentedRwLockReadGuard<'a, T> {
        let guard = s.guard.take().expect("guard is present until drop");
        record_hold(
            s.name,
            "write",
            s.acquired,
            s.hold_threshold,
            s.metrics.write_hold,
        );
        let read_guard = RwLockWriteGuard::downgrade(guard);
        InstrumentedRwLockReadGuard {
            guard: Some(read_guard),
            metrics: s.metrics,
            name: s.name,
            hold_threshold: s.hold_threshold,
            acquired: Instant::now(),
        }
    }
}

impl<T> Deref for InstrumentedRwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().expect("guard is present until drop")
    }
}

impl<T> DerefMut for InstrumentedRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().expect("guard is present until drop")
    }
}

impl<T> Drop for InstrumentedRwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            drop(guard);
            record_hold(
                self.name,
                "write",
                self.acquired,
                self.hold_threshold,
                self.metrics.write_hold,
            );
        }
    }
}

// ---- Upgradable read guard ----

pub struct InstrumentedRwLockUpgradableReadGuard<'a, T> {
    guard: Option<RwLockUpgradableReadGuard<'a, T>>,
    metrics: &'static LockMetrics,
    name: &'static str,
    hold_threshold: Duration,
    acquired: Instant,
}

impl<'a, T> InstrumentedRwLockUpgradableReadGuard<'a, T> {
    /// Atomically upgrade to a write guard, preserving instrumentation. The
    /// upgradable-read hold time is recorded at the point of upgrade and a
    /// fresh write-hold measurement begins.
    pub fn upgrade(mut s: Self) -> InstrumentedRwLockWriteGuard<'a, T> {
        let guard = s.guard.take().expect("guard is present until drop");
        record_hold(
            s.name,
            "upgradable",
            s.acquired,
            s.hold_threshold,
            s.metrics.upgradable_hold,
        );
        let write_guard = RwLockUpgradableReadGuard::upgrade(guard);
        InstrumentedRwLockWriteGuard {
            guard: Some(write_guard),
            metrics: s.metrics,
            name: s.name,
            hold_threshold: s.hold_threshold,
            acquired: Instant::now(),
        }
    }
}

impl<T> Deref for InstrumentedRwLockUpgradableReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().expect("guard is present until drop")
    }
}

impl<T> Drop for InstrumentedRwLockUpgradableReadGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            drop(guard);
            record_hold(
                self.name,
                "upgradable",
                self.acquired,
                self.hold_threshold,
                self.metrics.upgradable_hold,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::metrics::{exponential_buckets, try_create_histogram_with_buckets};

    static TEST_ACQUIRE: LockMetric = LazyLock::new(|| {
        try_create_histogram_with_buckets(
            "test_instrumented_lock_acquire_seconds",
            "Test acquire histogram",
            exponential_buckets(1e-6, 4.0, 7),
        )
    });
    static TEST_HOLD: LockMetric = LazyLock::new(|| {
        try_create_histogram_with_buckets(
            "test_instrumented_lock_hold_seconds",
            "Test hold histogram",
            exponential_buckets(1e-6, 4.0, 7),
        )
    });
    static TEST_METRICS: LockMetrics = LockMetrics {
        read_acquire: &TEST_ACQUIRE,
        write_acquire: &TEST_ACQUIRE,
        upgradable_acquire: &TEST_ACQUIRE,
        read_hold: &TEST_HOLD,
        write_hold: &TEST_HOLD,
        upgradable_hold: &TEST_HOLD,
    };

    fn lock(value: i32) -> InstrumentedRwLock<i32> {
        InstrumentedRwLock::new(value, &TEST_METRICS, "test", Duration::from_millis(50))
    }

    #[test]
    fn read_then_write_are_transparent() {
        let l = lock(1);
        assert_eq!(*l.read(), 1);
        {
            let mut w = l.write();
            *w = 42;
        }
        assert_eq!(*l.read(), 42);
    }

    #[test]
    fn downgrade_preserves_mutation() {
        let l = lock(0);
        let mut w = l.write();
        *w = 7;
        let r = InstrumentedRwLockWriteGuard::downgrade(w);
        assert_eq!(*r, 7);
    }

    #[test]
    fn upgrade_then_mutate_is_visible() {
        let l = lock(0);
        let u = l.upgradable_read();
        assert_eq!(*u, 0);
        let mut w = InstrumentedRwLockUpgradableReadGuard::upgrade(u);
        *w = 9;
        drop(w);
        assert_eq!(*l.read(), 9);
    }

    #[test]
    fn holding_past_threshold_does_not_panic() {
        // Exceeds the 50ms threshold so the backtrace/warn path in `record_hold`
        // is exercised on drop.
        let l = lock(0);
        let r = l.read();
        std::thread::sleep(Duration::from_millis(60));
        drop(r);
    }
}
