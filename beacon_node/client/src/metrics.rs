use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref SYNC_SLOTS_PER_SECOND: Result<IntGauge> = try_create_int_gauge(
        "sync_slots_per_second",
        "The number of blocks being imported per second"
    );
}
