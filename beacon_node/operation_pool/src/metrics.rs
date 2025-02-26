pub use metrics::*;
use std::sync::LazyLock;

pub static BUILD_REWARD_CACHE_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "op_pool_build_reward_cache_time",
        "Time to build the reward cache before packing attestations",
    )
});
pub static ATTESTATION_PREV_EPOCH_PACKING_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "op_pool_attestation_prev_epoch_packing_time",
        "Time to pack previous epoch attestations",
    )
});
pub static ATTESTATION_CURR_EPOCH_PACKING_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "op_pool_attestation_curr_epoch_packing_time",
        "Time to pack current epoch attestations",
    )
});
pub static NUM_PREV_EPOCH_ATTESTATIONS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "op_pool_prev_epoch_attestations",
        "Number of valid attestations considered for packing from the previous epoch",
    )
});
pub static NUM_CURR_EPOCH_ATTESTATIONS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "op_pool_curr_epoch_attestations",
        "Number of valid attestations considered for packing from the current epoch",
    )
});
pub static MAX_COVER_NON_ZERO_ITEMS: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "op_pool_max_cover_non_zero_items",
        "Number of non-trivial items considered in a max coverage optimisation",
        &["label"],
    )
});
