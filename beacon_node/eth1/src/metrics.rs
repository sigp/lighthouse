pub use lighthouse_metrics::*;

lazy_static! {
    /*
     * Eth1 blocks
     */
    pub static ref BLOCK_CACHE_LEN: Result<IntGauge> =
        try_create_int_gauge("eth1_block_cache_len", "Count of eth1 blocks in cache");
    pub static ref LATEST_CACHED_BLOCK_TIMESTAMP: Result<IntGauge> =
        try_create_int_gauge("eth1_latest_cached_block_timestamp", "Timestamp of latest block in eth1 cache");

    /*
     * Eth1 deposits
     */
    pub static ref DEPOSIT_CACHE_LEN: Result<IntGauge> =
        try_create_int_gauge("eth1_deposit_cache_len", "Number of deposits in the eth1 cache");
    pub static ref HIGHEST_PROCESSED_DEPOSIT_BLOCK: Result<IntGauge> =
        try_create_int_gauge("eth1_highest_processed_deposit_block", "Number of the last block checked for deposits");

    /*
     * Eth1 endpoint errors
     */
    pub static ref ENDPOINT_ERRORS: Result<IntCounterVec> = try_create_int_counter_vec(
        "eth1_endpoint_errors", "The number of eth1 request errors for each endpoint", &["endpoint"]
    );
    pub static ref ENDPOINT_REQUESTS: Result<IntCounterVec> = try_create_int_counter_vec(
        "eth1_endpoint_requests", "The number of eth1 requests for each endpoint", &["endpoint"]
    );

    /*
     * Eth1 rpc connection
     */

    pub static ref ETH1_CONNECTED: Result<IntGauge> = try_create_int_gauge(
        "sync_eth1_connected", "Set to 1 if connected to an eth1 node, otherwise set to 0"
    );

    pub static ref ETH1_FALLBACK_CONFIGURED: Result<IntGauge> = try_create_int_gauge(
        "sync_eth1_fallback_configured", "Number of configured eth1 fallbacks"
    );

    // Note: This metric only checks if an eth1 fallback is configured, not if it is connected and synced.
    // Checking for liveness of the fallback would require moving away from lazy checking of fallbacks.
    pub static ref ETH1_FALLBACK_CONNECTED: Result<IntGauge> = try_create_int_gauge(
        "eth1_sync_fallback_connected", "Set to 1 if an eth1 fallback is connected, otherwise set to 0"
    );

}
