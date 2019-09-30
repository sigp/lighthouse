pub use lighthouse_metrics::{set_gauge, try_create_int_gauge, *};

use std::fs;
use std::path::PathBuf;

lazy_static! {
    /*
     * General
     */
    pub static ref DISK_DB_SIZE: Result<IntGauge> =
        try_create_int_gauge("store_disk_db_size", "Size of the on-disk database (bytes)");
    pub static ref DISK_DB_WRITE_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_write_bytes_total",
        "Number of bytes attempted to be written to the on-disk DB"
    );
    pub static ref DISK_DB_READ_BYTES: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_read_bytes_total",
        "Number of bytes read from the on-disk DB"
    );
    pub static ref DISK_DB_READ_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_read_count_total",
        "Total number of reads to the on-disk DB"
    );
    pub static ref DISK_DB_WRITE_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_write_count_total",
        "Total number of writes to the on-disk DB"
    );
    pub static ref DISK_DB_EXISTS_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_exists_count_total",
        "Total number of checks if a key is in the on-disk DB"
    );
    pub static ref DISK_DB_DELETE_COUNT: Result<IntCounter> = try_create_int_counter(
        "store_disk_db_delete_count_total",
        "Total number of deletions from the on-disk DB"
    );
    /*
     * Beacon State
     */
    pub static ref BEACON_STATE_READ_TIMES: Result<Histogram> = try_create_histogram(
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
    pub static ref BEACON_STATE_WRITE_TIMES: Result<Histogram> = try_create_histogram(
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
pub fn scrape_for_metrics(db_path: &PathBuf) {
    let db_size = if let Ok(iter) = fs::read_dir(db_path) {
        iter.filter_map(std::result::Result::ok)
            .map(size_of_dir_entry)
            .sum()
    } else {
        0
    };
    set_gauge(&DISK_DB_SIZE, db_size as i64);
}

fn size_of_dir_entry(dir: fs::DirEntry) -> u64 {
    dir.metadata().map(|m| m.len()).unwrap_or(0)
}
