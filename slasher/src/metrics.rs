use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref SLASHER_RUN_TIME: Result<Histogram> = try_create_histogram(
        "slasher_process_batch_time",
        "Time taken to process a batch of blocks and attestations"
    );
    pub static ref SLASHER_NUM_ATTESTATIONS_DROPPED: Result<IntGauge> = try_create_int_gauge(
        "slasher_num_attestations_dropped",
        "Number of attestations dropped per batch"
    );
    pub static ref SLASHER_NUM_ATTESTATIONS_DEFERRED: Result<IntGauge> = try_create_int_gauge(
        "slasher_num_attestations_deferred",
        "Number of attestations deferred per batch"
    );
    pub static ref SLASHER_NUM_ATTESTATIONS_VALID: Result<IntGauge> = try_create_int_gauge(
        "slasher_num_attestations_valid",
        "Number of valid attestations per batch"
    );
}
