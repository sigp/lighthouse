pub use lighthouse_metrics::{set_gauge, try_create_int_gauge, *};

use std::fs;
use std::path::PathBuf;

lazy_static! {
    pub static ref DISK_DB_SIZE: Result<IntGauge> =
        try_create_int_gauge("database_size", "Size of the on-disk database (bytes)");
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
