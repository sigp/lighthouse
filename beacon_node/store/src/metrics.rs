pub use lighthouse_metrics::{set_gauge, try_create_int_gauge, *};

use directory::size_of_dir;
use lazy_static::lazy_static;
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
}

/// Updates the global metrics registry with store-related information.
pub fn scrape_for_metrics(db_path: &Path, freezer_db_path: &Path) {
    let db_size = size_of_dir(db_path);
    set_gauge(&DISK_DB_SIZE, db_size as i64);
    let freezer_db_size = size_of_dir(freezer_db_path);
    set_gauge(&FREEZER_DB_SIZE, freezer_db_size as i64);
}
