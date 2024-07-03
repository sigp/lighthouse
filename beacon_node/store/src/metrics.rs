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
    pub static ref BEACON_STATE_CACHE_HIT_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_state_cache_hit_total",
        "Number of hits to the store's state cache"
    );
    pub static ref BEACON_STATE_CACHE_CLONE_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_state_cache_clone_time",
        "Time to load a beacon block from the block cache"
    );
    pub static ref BEACON_STATE_READ_TIMES: Result<Histogram> = try_create_histogram(
        "store_beacon_state_read_seconds",
        "Total time required to read a BeaconState from the database"
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
    pub static ref BEACON_BLOBS_CACHE_HIT_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_blobs_cache_hit_total",
        "Number of hits to the store's blob cache"
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

    /*
    * Caches
    */

    /*
    * Store metrics
    */
    pub static ref STORE_BEACON_BLOCK_CACHE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "store_beacon_block_cache_size",
        "Current count of items in beacon store block cache",
    );
    pub static ref STORE_BEACON_BLOB_CACHE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "store_beacon_blob_cache_size",
        "Current count of items in beacon store blob cache",
    );
    pub static ref STORE_BEACON_STATE_CACHE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "store_beacon_state_cache_size",
        "Current count of items in beacon store state cache",
    );
    pub static ref STORE_BEACON_HISTORIC_STATE_CACHE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "store_beacon_historic_state_cache_size",
        "Current count of items in beacon store historic state cache",
    );
    pub static ref STORE_BEACON_DIFF_BUFFER_CACHE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "store_beacon_diff_buffer_cache_size",
        "Current count of items in beacon store diff buffer cache",
    );
    pub static ref STORE_BEACON_DIFF_BUFFER_CACHE_BYTE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "store_beacon_diff_buffer_cache_byte_size",
        "Current byte size sum of all elements in beacon store diff buffer cache",
    );
    pub static ref STORE_BEACON_STATE_COMPRESS_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_state_compress_seconds",
        "Time taken to compress a state snapshot",
    );
    pub static ref STORE_BEACON_STATE_DECOMPRESS_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_state_decompress_seconds",
        "Time taken to decompress a state snapshot",
    );
    pub static ref STORE_BEACON_DIFF_BUFFER_APPLY_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_diff_buffer_apply_seconds",
        "Time taken to apply diff buffer to a state buffer",
    );
    pub static ref STORE_BEACON_DIFF_BUFFER_COMPUTE_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_diff_buffer_compute_seconds",
        "Time taken to compute diff buffer to a state buffer",
    );
    pub static ref STORE_BEACON_HDIFF_BUFFER_LOAD_TIME: Result<Histogram> = try_create_histogram(
        "store_beacon_hdiff_buffer_load_seconds",
        "Time taken to load an hdiff buffer from disk",
    );
    pub static ref STORE_BEACON_DIFF_BUFFER_CACHE_HIT: Result<IntCounter> = try_create_int_counter(
        "store_beacon_diff_buffer_cache_hit_total",
        "Total count of diff buffer cache hits",
    );
    pub static ref STORE_BEACON_DIFF_BUFFER_CACHE_MISS: Result<IntCounter> = try_create_int_counter(
        "store_beacon_diff_buffer_cache_miss_total",
        "Total count of diff buffer cache miss",
    );
    pub static ref STORE_BEACON_REPLAYED_BLOCKS: Result<IntCounter> = try_create_int_counter(
        "store_beacon_replayed_blocks_total",
        "Total count of replayed blocks",
    );
}

/// Updates the global metrics registry with store-related information.
pub fn scrape_for_metrics(db_path: &Path, freezer_db_path: &Path) {
    let db_size = size_of_dir(db_path);
    set_gauge(&DISK_DB_SIZE, db_size as i64);
    let freezer_db_size = size_of_dir(freezer_db_path);
    set_gauge(&FREEZER_DB_SIZE, freezer_db_size as i64);
}
