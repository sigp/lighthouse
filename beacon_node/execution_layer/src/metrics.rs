pub use lighthouse_metrics::*;

pub const GET_PAYLOAD: &str = "get_payload";
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
        "Duration between a fcU call with PayloadAttributes and when the block should be produced",
    );
}
