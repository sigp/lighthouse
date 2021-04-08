use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref SYNC_SLOTS_PER_SECOND: Result<IntGauge> = try_create_int_gauge(
        "sync_slots_per_second",
        "The number of blocks being imported per second"
    );

    pub static ref IS_SYNCED: Result<IntGauge> = try_create_int_gauge(
        "sync_eth2_synced",
        "Metric to check if the beacon chain is synced to head. 0 if not synced and non-zero if synced"
    );

    pub static ref NOTIFIER_HEAD_SLOT: Result<IntGauge> = try_create_int_gauge(
        "notifier_head_slot",
        "The head slot sourced from the beacon chain notifier"
    );
}
