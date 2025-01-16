pub use metrics::*;
use std::sync::LazyLock;

pub static HTTP_API_PATHS_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "http_api_paths_total",
        "Count of HTTP requests received",
        &["path"],
    )
});
pub static HTTP_API_STATUS_CODES_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "http_api_status_codes_total",
        "Count of HTTP status codes returned",
        &["status"],
    )
});
pub static HTTP_API_PATHS_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "http_api_paths_times",
        "Duration to process HTTP requests per path",
        &["path"],
    )
});

pub static HTTP_API_BLOCK_BROADCAST_DELAY_TIMES: LazyLock<Result<HistogramVec>> =
    LazyLock::new(|| {
        try_create_histogram_vec(
            "http_api_block_broadcast_delay_times",
            "Time between start of the slot and when the block completed broadcast and processing",
            &["provenance"],
        )
    });
pub static HTTP_API_BLOCK_GOSSIP_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec_with_buckets(
        "http_api_block_gossip_times",
        "Time between receiving the block on HTTP and publishing it on gossip",
        decimal_buckets(-2, 2),
        &["provenance"],
    )
});
pub static HTTP_API_STATE_SSZ_ENCODE_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "http_api_state_ssz_encode_times",
        "Time to SSZ encode a BeaconState for a response",
    )
});
pub static HTTP_API_STATE_ROOT_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "http_api_state_root_times",
        "Time to load a state root for a request",
    )
});
