//! Prometheus metrics for the Fast Confirmation Rule.

pub use metrics::*;
use std::sync::LazyLock;

pub static FCR_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram_with_buckets(
        "beacon_fcr_seconds",
        "Runtime of the fast confirmation rule computation",
        exponential_buckets(1e-3, 2.0, 12),
    )
});
pub static FCR_CONFIRMED_ROOT_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fcr_confirmed_root_slot",
        "Slot of the current FCR confirmed root",
    )
});
pub static FCR_CONFIRMED_ROOT_CHANGES: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fcr_confirmed_root_changes_total",
        "Count of times the FCR confirmed root has changed",
    )
});
pub static FCR_ERRORS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_fcr_errors_total",
        "Count of FCR errors by error category",
        &["error"],
    )
});
pub static FCR_CONFIRMATION_DELAY_SLOTS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fcr_confirmation_delay_slots",
        "Confirmation delay: current head slot minus confirmed root slot",
    )
});
pub static FCR_PHASE1_REVERT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fcr_phase1_revert_total",
        "Count of FCR phase 1 (revert to finalized) activations",
    )
});
pub static FCR_PHASE2_RESTART: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fcr_phase2_restart_total",
        "Count of FCR phase 2 (restart from justified) activations",
    )
});
pub static FCR_PHASE3_ADVANCE: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fcr_phase3_advance_total",
        "Count of FCR phase 3 (advance confirmed root) activations",
    )
});
pub static FCR_BALANCE_SOURCE_AGE_EPOCHS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fcr_balance_source_age_epochs",
        "Age of the current balance source in epochs (current_epoch - balance_source_epoch)",
    )
});
