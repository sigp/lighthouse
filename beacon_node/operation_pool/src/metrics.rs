use lazy_static::lazy_static;

pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref ATTESTATIONS_AVAILABLE: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "op_pool_attestations_available",
        "Number of attestations in the pool being considered for a block",
        &["epoch"]
    );
    pub static ref ATTESTATION_FILTER_TIME: Result<Histogram> = try_create_histogram(
        "op_pool_attestation_filter_time",
        "Time to filter attestations in pool for validity"
    );
    pub static ref ATTESTATION_PREV_EPOCH_PACKING_TIME: Result<Histogram> = try_create_histogram(
        "op_pool_attestation_prev_epoch_packing_time",
        "Time to pack previous epoch attestations"
    );
    pub static ref ATTESTATION_CURR_EPOCH_PACKING_TIME: Result<Histogram> = try_create_histogram(
        "op_pool_attestation_curr_epoch_packing_time",
        "Time to pack current epoch attestations"
    );
}
