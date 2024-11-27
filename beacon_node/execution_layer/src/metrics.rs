pub use metrics::*;
use std::sync::LazyLock;

pub const HIT: &str = "hit";
pub const MISS: &str = "miss";
pub const GET_PAYLOAD: &str = "get_payload";
pub const GET_BLINDED_PAYLOAD: &str = "get_blinded_payload";
pub const GET_BLINDED_PAYLOAD_LOCAL: &str = "get_blinded_payload_local";
pub const GET_BLINDED_PAYLOAD_BUILDER: &str = "get_blinded_payload_builder";
pub const POST_BLINDED_PAYLOAD_BUILDER: &str = "post_blinded_payload_builder";
pub const NEW_PAYLOAD: &str = "new_payload";
pub const FORKCHOICE_UPDATED: &str = "forkchoice_updated";
pub const GET_TERMINAL_POW_BLOCK_HASH: &str = "get_terminal_pow_block_hash";
pub const IS_VALID_TERMINAL_POW_BLOCK_HASH: &str = "is_valid_terminal_pow_block_hash";
pub const LOCAL: &str = "local";
pub const BUILDER: &str = "builder";
pub const SUCCESS: &str = "success";
pub const FAILURE: &str = "failure";

pub static EXECUTION_LAYER_PROPOSER_INSERTED: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "execution_layer_proposer_inserted",
        "Count of times a new proposer is known",
    )
});
pub static EXECUTION_LAYER_PROPOSER_DATA_UPDATED: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| {
        try_create_int_counter(
            "execution_layer_proposer_data_updated",
            "Count of times new proposer data is supplied",
        )
    });
pub static EXECUTION_LAYER_REQUEST_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec_with_buckets(
        "execution_layer_request_times",
        "Duration of calls to ELs",
        decimal_buckets(-2, 1),
        &["method"],
    )
});
pub static EXECUTION_LAYER_PAYLOAD_ATTRIBUTES_LOOKAHEAD: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
        "execution_layer_payload_attributes_lookahead",
        "Duration between an fcU call with PayloadAttributes and when the block should be produced",
    )
    });
pub static EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID: LazyLock<Result<IntCounterVec>> = LazyLock::new(
    || {
        try_create_int_counter_vec(
        "execution_layer_pre_prepared_payload_id",
        "Indicates hits or misses for already having prepared a payload id before payload production",
        &["event"]
    )
    },
);
pub static EXECUTION_LAYER_GET_PAYLOAD_BODIES_BY_RANGE: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "execution_layer_get_payload_bodies_by_range_time",
            "Time to fetch a range of payload bodies from the EE",
        )
    });
pub static EXECUTION_LAYER_VERIFY_BLOCK_HASH: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram_with_buckets(
        "execution_layer_verify_block_hash_time",
        "Time to verify the execution block hash in Lighthouse, without the EL",
        Ok(vec![
            10e-6, 50e-6, 100e-6, 500e-6, 1e-3, 5e-3, 10e-3, 50e-3, 100e-3, 500e-3,
        ]),
    )
});
pub static EXECUTION_LAYER_PAYLOAD_STATUS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "execution_layer_payload_status",
        "Indicates the payload status returned for a particular method",
        &["method", "status"],
    )
});
pub static EXECUTION_LAYER_GET_PAYLOAD_OUTCOME: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "execution_layer_get_payload_outcome",
            "The success/failure outcomes from calling get_payload",
            &["outcome"],
        )
    });
pub static EXECUTION_LAYER_BUILDER_REVEAL_PAYLOAD_OUTCOME: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "execution_layer_builder_reveal_payload_outcome",
            "The success/failure outcomes from a builder un-blinding a payload",
            &["outcome"],
        )
    });
pub static EXECUTION_LAYER_GET_PAYLOAD_SOURCE: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "execution_layer_get_payload_source",
            "The source of each payload returned from get_payload",
            &["source"],
        )
    });
pub static EXECUTION_LAYER_GET_PAYLOAD_BUILDER_REJECTIONS: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "execution_layer_get_payload_builder_rejections",
            "The reasons why a payload from a builder was rejected",
            &["reason"],
        )
    });
pub static EXECUTION_LAYER_PAYLOAD_BIDS: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "execution_layer_payload_bids",
        "The gwei bid value of payloads received by local EEs or builders. Only shows values up to i64::MAX.",
        &["source"]
    )
});
