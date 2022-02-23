pub use lighthouse_metrics::{set_gauge, try_create_int_gauge, *};

use directory::size_of_dir;
use std::path::Path;

lazy_static! {
    /*
     * General
     */
    pub static ref DISK_DB_SIZE: Result<IntGauge> =
        try_create_int_gauge("store_disk_db_size", "Size of the hot on-disk database (bytes)");
    pub static ref FREEZER_DB_SIZE: Result<IntGauge> =
        try_create_int_gauge("store_freezer_db_size", "Size of the on-disk freezer database (bytes)");
    pub static ref DISK_DB_WRITE_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_write_bytes_total",
        "Number of bytes attempted to be written to the hot on-disk DB"
    );
    pub static ref DISK_DB_READ_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_read_bytes_total",
        "Number of bytes read from the hot on-disk DB"
    );
    pub static ref DISK_DB_READ_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_read_count_total",
        "Total number of reads to the hot on-disk DB"
    );
    pub static ref DISK_DB_WRITE_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_write_count_total",
        "Total number of writes to the hot on-disk DB"
    );
    pub static ref DISK_DB_READ_TIMES: Result<Histogram> = try_create_histogram(
        "store_disk_db_read_seconds",
        "Time taken to write bytes to store."
    );
    pub static ref DISK_DB_WRITE_TIMES: Result<Histogram> = try_create_histogram(
        "store_disk_db_write_seconds",
        "Time taken to write bytes to store."
    );
    pub static ref DISK_DB_EXISTS_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_exists_count_total",
        "Total number of checks if a key is in the hot on-disk DB"
    );
    pub static ref DISK_DB_DELETE_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_delete_count_total",
        "Total number of deletions from the hot on-disk DB"
    );
    /*
     * Beacon State
     */
    pub static ref BEACON_STATE_GET_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_get_total",
        "Total number of beacon states requested from the store (cache or DB)"
    );
    pub static ref BEACON_STATE_HOT_GET_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_hot_get_total",
        "Total number of hot beacon states requested from the store (cache or DB)"
    );
    pub static ref BEACON_STATE_READ_TIMES: Result<Histogram> = try_create_histogram(
        "store_beacon_state_read_seconds",
        "Total time required to read a full BeaconState from the database"
    );
    pub static ref BEACON_HOT_STATE_READ_TIMES: Result<Histogram> = try_create_histogram(
        "store_beacon_hot_state_read_seconds",
        "Total time required to read a hot BeaconState from the database"
    );
    pub static ref BEACON_STATE_READ_OVERHEAD_TIMES: Result<Histogram> = try_create_histogram(
        "store_beacon_state_read_overhead_seconds",
        "Overhead on reading a beacon state from the DB (e.g., decoding)"
    );
    pub static ref BEACON_STATE_READ_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_read_total",
        "Total number of beacon state reads from the DB"
    );
    pub static ref BEACON_STATE_READ_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_read_bytes_total",
        "Total number of beacon state bytes read from the DB"
    );
    pub static ref BEACON_STATE_WRITE_OVERHEAD_TIMES: Result<Histogram> = try_create_histogram(
        "store_beacon_state_write_overhead_seconds",
        "Overhead on writing a beacon state to the DB (e.g., encoding)"
    );
    pub static ref BEACON_STATE_WRITE_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_write_total",
        "Total number of beacon state writes the DB"
    );
    pub static ref BEACON_STATE_WRITE_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_write_bytes_total",
        "Total number of beacon state bytes written to the DB"
    );
    /*
     * Beacon state diffs
     */
    pub static ref BEACON_STATE_DIFF_WRITE_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_diff_write_bytes_total",
        "Total number of bytes written for beacon state diffs"
    );
    pub static ref BEACON_STATE_DIFF_WRITE_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_diff_write_count_total",
        "Total number of beacon state diffs written"
    );
    pub static ref BEACON_STATE_DIFF_COMPRESSION_RATIO: Result<Gauge> = try_create_float_gauge(
        "store_beacon_state_diff_compression_ratio",
        "Compression ratio for beacon state diffs (higher is better)"
    );
    pub static ref BEACON_STATE_DIFF_COMPUTE_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_state_diff_compute_time",
        "Time to calculate a beacon state diff"
    );
    pub static ref BEACON_STATE_DIFF_ENCODE_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_state_diff_encode_time",
        "Time to encode a beacon state diff as SSZ"
    );
    pub static ref BEACON_STATE_DIFF_COMPRESSION_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_state_diff_compression_time",
        "Time to compress beacon state SSZ using Flate2"
    );
    /*
     * Beacon Block
     */
    pub static ref BEACON_BLOCK_GET_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_block_get_total",
        "Total number of beacon blocks requested from the store (cache or DB)"
    );
    pub static ref BEACON_BLOCK_CACHE_HIT_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_block_cache_hit_total",
        "Number of hits to the store's block cache"
    );
    pub static ref BEACON_BLOCK_READ_TIMES: Result<Histogram> = try_create_histogram(
        "store_beacon_block_read_overhead_seconds",
        "Overhead on reading a beacon block from the DB (e.g., decoding)"
    );
    pub static ref BEACON_BLOCK_READ_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_block_read_total",
        "Total number of beacon block reads from the DB"
    );
    pub static ref BEACON_BLOCK_READ_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_beacon_block_read_bytes_total",
        "Total number of beacon block bytes read from the DB"
    );
    pub static ref BEACON_BLOCK_WRITE_TIMES: Result<Histogram> = try_create_histogram(
        "store_beacon_block_write_overhead_seconds",
        "Overhead on writing a beacon block to the DB (e.g., encoding)"
    );
    pub static ref BEACON_BLOCK_WRITE_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_block_write_total",
        "Total number of beacon block writes the DB"
    );
    pub static ref BEACON_BLOCK_WRITE_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_beacon_block_write_bytes_total",
        "Total number of beacon block bytes written to the DB"
    );
}

/// Updates the global metrics registry with store-related information.
pub fn scrape_for_metrics(db_path: &Path, freezer_db_path: &Path) {
    let db_size = size_of_dir(db_path);
    set_gauge(&DISK_DB_SIZE, db_size as i64);
    let freezer_db_size = size_of_dir(freezer_db_path);
    set_gauge(&FREEZER_DB_SIZE, freezer_db_size as i64);
}
