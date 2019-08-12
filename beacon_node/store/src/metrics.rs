pub use lighthouse_metrics::{set_gauge, try_create_int_gauge, *};

use std::fs;
use std::path::PathBuf;

lazy_static! {
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
}

/// Updates the global metrics registry with store-related information.
pub fn scrape_for_metrics(db_path: &PathBuf) {
    let db_size = if let Ok(iter) = fs::read_dir(db_path) {
        iter.filter_map(std::result::Result::ok)
            .map(size_of_dir_entry)
            .fold(0_u64, |sum, val| sum + val)
    } else {
        0
    };
    set_gauge(&DISK_DB_SIZE, db_size as i64);
}

fn size_of_dir_entry(dir: fs::DirEntry) -> u64 {
    dir.metadata().map(|m| m.len()).unwrap_or(0)
}
