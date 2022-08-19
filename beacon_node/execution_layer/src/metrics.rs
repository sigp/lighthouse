pub use lighthouse_metrics::*;

pub const HIT: &str = "hit";
pub const MISS: &str = "miss";
pub const GET_PAYLOAD: &str = "get_payload";
pub const GET_BLINDED_PAYLOAD: &str = "get_blinded_payload";
pub const NEW_PAYLOAD: &str = "new_payload";
pub const FORKCHOICE_UPDATED: &str = "forkchoice_updated";
pub const GET_TERMINAL_POW_BLOCK_HASH: &str = "get_terminal_pow_block_hash";
pub const IS_VALID_TERMINAL_POW_BLOCK_HASH: &str = "is_valid_terminal_pow_block_hash";

lazy_static::lazy_static! {
    pub static ref EXECUTION_LAYER_PROPOSER_INSERTED: Result<IntCounter> = try_create_int_counter(
        "execution_layer_proposer_inserted",
        "Count of times a new proposer is known",
    );
    pub static ref EXECUTION_LAYER_PROPOSER_DATA_UPDATED: Result<IntCounter> = try_create_int_counter(
        "execution_layer_proposer_data_updated",
        "Count of times new proposer data is supplied",
    );
    pub static ref EXECUTION_LAYER_REQUEST_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "execution_layer_request_times",
        "Duration of calls to ELs",
        &["method"]
    );
    pub static ref EXECUTION_LAYER_PAYLOAD_ATTRIBUTES_LOOKAHEAD: Result<Histogram> = try_create_histogram(
        "execution_layer_payload_attributes_lookahead",
        "Duration between an fcU call with PayloadAttributes and when the block should be produced",
    );
    pub static ref EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID: Result<IntCounterVec> = try_create_int_counter_vec(
        "execution_layer_pre_prepared_payload_id",
        "Indicates hits or misses for already having prepared a payload id before payload production",
        &["event"]
    );
    pub static ref EXECUTION_LAYER_GET_PAYLOAD_BY_BLOCK_HASH: Result<Histogram> = try_create_histogram(
        "execution_layer_get_payload_by_block_hash_time",
        "Time to reconstruct a payload from the EE using eth_getBlockByHash"
    );
    pub static ref EXECUTION_LAYER_PAYLOAD_STATUS: Result<IntCounterVec> = try_create_int_counter_vec(
        "execution_layer_payload_status",
        "Indicates the payload status returned for a particular method",
        &["method", "status"]
    );
}
