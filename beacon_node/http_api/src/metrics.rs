pub use lighthouse_metrics::*;

lazy_static::lazy_static! {
    pub static ref HTTP_API_PATHS_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "http_api_paths_total",
        "Count of HTTP requests received",
        &["path"]
    );
    pub static ref HTTP_API_STATUS_CODES_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "http_api_status_codes_total",
        "Count of HTTP status codes returned",
        &["status"]
    );
    pub static ref HTTP_API_PATHS_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "http_api_paths_times",
        "Duration to process HTTP requests per path",
        &["path"]
    );

    pub static ref HTTP_API_BEACON_PROPOSER_CACHE_TIMES: Result<Histogram> = try_create_histogram(
        "http_api_beacon_proposer_cache_build_times",
        "Duration to process HTTP requests per path",
    );
    pub static ref HTTP_API_BEACON_PROPOSER_CACHE_HITS_TOTAL: Result<IntCounter> = try_create_int_counter(
        "http_api_beacon_proposer_cache_hits_total",
        "Count of times the proposer cache has been hit",
    );
    pub static ref HTTP_API_BEACON_PROPOSER_CACHE_MISSES_TOTAL: Result<IntCounter> = try_create_int_counter(
        "http_api_beacon_proposer_cache_misses_total",
        "Count of times the proposer cache has been missed",
    );
}
