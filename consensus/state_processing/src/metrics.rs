pub use metrics::*;
use std::sync::LazyLock;

/*
 * Participation Metrics
 */
pub static PARTICIPATION_PREV_EPOCH_HEAD_ATTESTING_GWEI_TOTAL: LazyLock<Result<IntGauge>> =
    LazyLock::new(|| {
        try_create_int_gauge(
        "beacon_participation_prev_epoch_head_attesting_gwei_total",
        "Total effective balance (gwei) of validators who attested to the head in the previous epoch"
    )
    });
pub static PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_TOTAL: LazyLock<Result<IntGauge>> =
    LazyLock::new(|| {
        try_create_int_gauge(
        "beacon_participation_prev_epoch_target_attesting_gwei_total",
        "Total effective balance (gwei) of validators who attested to the target in the previous epoch"
    )
    });
pub static PARTICIPATION_PREV_EPOCH_SOURCE_ATTESTING_GWEI_TOTAL: LazyLock<Result<IntGauge>> =
    LazyLock::new(|| {
        try_create_int_gauge(
        "beacon_participation_prev_epoch_source_attesting_gwei_total",
        "Total effective balance (gwei) of validators who attested to the source in the previous epoch"
    )
    });
pub static PARTICIPATION_CURRENT_EPOCH_TOTAL_ACTIVE_GWEI_TOTAL: LazyLock<Result<IntGauge>> =
    LazyLock::new(|| {
        try_create_int_gauge(
            "beacon_participation_current_epoch_active_gwei_total",
            "Total effective balance (gwei) of validators who are active in the current epoch",
        )
    });
/*
 * Processing metrics
 */
pub static PROCESS_EPOCH_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "beacon_state_processing_process_epoch",
        "Time required for process_epoch",
    )
});
pub static BUILD_EPOCH_CACHE_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "beacon_state_processing_epoch_cache",
        "Time required to build the epoch cache",
    )
});
pub static BUILD_PROGRESSIVE_BALANCES_CACHE_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "beacon_state_processing_progressive_balances_cache",
            "Time required to build the progressive balances cache",
        )
    });

/*
 * Participation Metrics (progressive balances)
 */
pub static PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL: LazyLock<
    Result<IntGauge>,
> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_participation_prev_epoch_target_attesting_gwei_progressive_total",
        "Progressive total effective balance (gwei) of validators who attested to the target in the previous epoch"
    )
});
pub static PARTICIPATION_CURR_EPOCH_TARGET_ATTESTING_GWEI_PROGRESSIVE_TOTAL: LazyLock<
    Result<IntGauge>,
> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_participation_curr_epoch_target_attesting_gwei_progressive_total",
        "Progressive total effective balance (gwei) of validators who attested to the target in the current epoch"
    )
});
