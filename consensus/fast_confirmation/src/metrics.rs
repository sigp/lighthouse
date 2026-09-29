//! Prometheus metrics for the Fast Confirmation Rule.

pub use metrics::*;
use std::sync::LazyLock;

pub static FAST_CONFIRMATION_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram_with_buckets(
        "beacon_fast_confirmation_seconds",
        "Runtime of the fast confirmation rule computation",
        exponential_buckets(1e-3, 2.0, 12),
    )
});
pub static FAST_CONFIRMATION_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fast_confirmation_slot",
        "Slot of the block sent to the EL as the FCU safe block hash",
    )
});
pub static FAST_CONFIRMATION_ROOT_CHANGES: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_root_changes_total",
        "Count of times the root sent as the FCU safe block hash has changed",
    )
});
pub static FAST_CONFIRMATION_ERRORS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_fast_confirmation_errors_total",
        "Count of FCR errors by error category",
        &["error"],
    )
});
pub static FAST_CONFIRMATION_DELAY_SLOTS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fast_confirmation_delay_slots",
        "Confirmation delay: current slot minus the slot of the block sent as the FCU safe block hash",
    )
});
pub static FAST_CONFIRMATION_SETTLED_DELAY_SLOTS: LazyLock<Result<Histogram>> = LazyLock::new(
    || {
        try_create_histogram_with_buckets(
            "beacon_fast_confirmation_settled_delay_slots",
            "Distribution of the FCR confirmation delay (current slot minus confirmed root slot, in \
         slots), sampled once per slot at the FCR per-slot update so block-import recomputes don't \
         bias the distribution",
            Ok(vec![1.0, 2.0, 3.0, 4.0, 5.0, 8.0, 12.0]),
        )
    },
);
pub(crate) static FAST_CONFIRMATION_FALLBACKS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_fallbacks_total",
        "Total number of fallbacks to finality",
    )
});
pub static FAST_CONFIRMATION_REORG_DISTANCE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_fast_confirmation_reorg_distance",
        "Slots from the deepest root sent as the FCU safe block hash back to its fork point with the head",
    )
});
pub(crate) static FAST_CONFIRMATION_FALLBACK_REASONS: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "beacon_fast_confirmation_fallback_reasons_total",
            "Breakdown of `beacon_fast_confirmation_fallbacks_total` by reason",
            &["reason"],
        )
    });
pub static FAST_CONFIRMATION_ROOT_REORGS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_root_reorgs_total",
        "Count of times the newly confirmed root was on a different branch from the deepest root \
         sent as the FCU safe block hash, i.e. a block FCR had confirmed was reorged out",
    )
});
pub static FAST_CONFIRMATION_REORGS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_reorgs_total",
        "Count of times the head left the chain of the deepest root sent as the FCU safe block hash",
    )
});
pub(crate) static FAST_CONFIRMATION_FALLBACK_SUPPORT_RATIO: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram_with_buckets(
            "beacon_fast_confirmation_fallback_support_ratio",
            "support / safety_threshold of the block that triggered a below_safety_threshold \
         fallback; values near 1.0 are marginal, lower values indicate real support loss",
            Ok(vec![0.5, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99, 1.0]),
        )
    });
pub(crate) static FAST_CONFIRMATION_RESTARTS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_restarts_total",
        "Total number of restarts from a safe unrealized justified block",
    )
});
pub(crate) static FAST_CONFIRMATION_ADVANCES: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_advances_total",
        "Count of FCR advances of the confirmed root to a descendant",
    )
});
pub static FAST_CONFIRMATION_SKIPS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_fast_confirmation_skips_total",
        "Count of head recomputes that skipped FCR because the head was behind the wall clock",
    )
});
