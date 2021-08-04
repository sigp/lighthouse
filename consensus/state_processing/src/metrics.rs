#![cfg(feature = "metrics")]

use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    /*
     * Participation Metrics
     */
    pub static ref PARTICIPATION_PREV_EPOCH_HEAD_ATTESTING_GWEI_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_participation_prev_epoch_head_attesting_gwei_total",
        "Total effective balance (gwei) of validators who attested to the head in the previous epoch"
    );
    pub static ref PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_participation_prev_epoch_target_attesting_gwei_total",
        "Total effective balance (gwei) of validators who attested to the target in the previous epoch"
    );
    pub static ref PARTICIPATION_PREV_EPOCH_SOURCE_ATTESTING_GWEI_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_participation_prev_epoch_source_attesting_gwei_total",
        "Total effective balance (gwei) of validators who attested to the source in the previous epoch"
    );
    pub static ref PARTICIPATION_PREV_EPOCH_ACTIVE_GWEI_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_participation_prev_epoch_active_gwei_total",
        "Total effective balance (gwei) of validators active in the previous epoch"
    );
}
