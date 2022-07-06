use lazy_static::lazy_static;

pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref BUILD_REWARD_CACHE_TIME: Result<Histogram> = try_create_histogram(
        "op_pool_build_reward_cache_time",
        "Time to build the reward cache before packing attestations"
    );
    pub static ref ATTESTATION_PREV_EPOCH_PACKING_TIME: Result<Histogram> = try_create_histogram(
        "op_pool_attestation_prev_epoch_packing_time",
        "Time to pack previous epoch attestations"
    );
    pub static ref ATTESTATION_CURR_EPOCH_PACKING_TIME: Result<Histogram> = try_create_histogram(
        "op_pool_attestation_curr_epoch_packing_time",
        "Time to pack current epoch attestations"
    );
    pub static ref NUM_PREV_EPOCH_ATTESTATIONS: Result<IntGauge> = try_create_int_gauge(
        "op_pool_prev_epoch_attestations",
        "Number of valid attestations considered for packing from the previous epoch"
    );
    pub static ref NUM_CURR_EPOCH_ATTESTATIONS: Result<IntGauge> = try_create_int_gauge(
        "op_pool_curr_epoch_attestations",
        "Number of valid attestations considered for packing from the current epoch"
    );
    pub static ref MAX_COVER_NON_ZERO_ITEMS: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "op_pool_max_cover_non_zero_items",
        "Number of non-trivial items considered in a max coverage optimisation",
        &["label"]
    );
}
