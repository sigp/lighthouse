pub use metrics::{set_gauge, try_create_int_gauge, *};

use directory::size_of_dir;
use std::path::Path;
use std::sync::LazyLock;

// Labels used for histogram timer vecs that are tracked per DB (hot and cold).
pub const HOT_METRIC: &[&str] = &["hot"];
pub const COLD_METRIC: &[&str] = &["cold"];

/*
 * General
 */
pub static DISK_DB_SIZE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_disk_db_size",
        "Size of the hot on-disk database (bytes)",
    )
});
pub static FREEZER_DB_SIZE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_freezer_db_size",
        "Size of the on-disk freezer database (bytes)",
    )
});
pub static DISK_DB_WRITE_BYTES: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_write_bytes_total",
        "Number of bytes attempted to be written to the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_READ_BYTES: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_read_bytes_total",
        "Number of bytes read from the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_KEY_READ_BYTES: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_key_read_bytes_total",
        "Number of key bytes read from the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_READ_COUNT: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_read_count_total",
        "Total number of reads to the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_KEY_READ_COUNT: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_read_count_total",
        "Total number of key reads to the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_WRITE_COUNT: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_write_count_total",
        "Total number of writes to the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_READ_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_disk_db_read_seconds",
        "Time taken to read bytes from store.",
    )
});
pub static DISK_DB_WRITE_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_disk_db_write_seconds",
        "Time taken to write bytes to store.",
    )
});
pub static DISK_DB_EXISTS_COUNT: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_exists_count_total",
        "Total number of checks if a key is in the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_DELETE_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_disk_db_delete_seconds",
        "Time taken to delete bytes from the store.",
    )
});
pub static DISK_DB_DELETE_COUNT: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_delete_count_total",
        "Total number of deletions from the hot on-disk DB",
        &["col"],
    )
});
pub static DISK_DB_COMPACT_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_disk_db_compact_seconds",
        "Time taken to run compaction on the DB.",
    )
});
pub static DISK_DB_TYPE: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "store_disk_db_type",
        "The on-disk database type being used",
        &["db_type"],
    )
});
/*
 * Anchor Info
 */
pub static STORE_BEACON_ANCHOR_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_beacon_anchor_slot",
        "Current anchor info anchor_slot value",
    )
});
pub static STORE_BEACON_OLDEST_BLOCK_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_beacon_oldest_block_slot",
        "Current anchor info oldest_block_slot value",
    )
});
pub static STORE_BEACON_STATE_LOWER_LIMIT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_beacon_state_lower_limit",
        "Current anchor info state_lower_limit value",
    )
});
/*
 * Beacon State
 */
pub static BEACON_STATE_GET_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "store_beacon_state_get_total",
        "Total number of beacon states requested from the store (cache or DB)",
    )
});
pub static BEACON_STATE_HOT_GET_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "store_beacon_state_hot_get_total",
        "Total number of hot beacon states requested from the store (cache or DB)",
    )
});

/*
 * HDiffs
 */
pub static BEACON_HDIFF_READ_TIME: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "store_hdiff_read_seconds",
        "Time taken to read hdiff bytes from disk",
        &["db"],
    )
});
pub static BEACON_HDIFF_DECODE_TIME: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "store_hdiff_decode_seconds",
        "Time taken to decode hdiff bytes",
        &["db"],
    )
});
pub static BEACON_HDIFF_APPLY_TIME: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "store_hdiff_apply_seconds",
        "Time taken to apply an hdiff to a buffer",
        &["db"],
    )
});
pub static BEACON_HDIFF_COMPUTE_TIME: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "store_hdiff_compute_seconds",
        "Time taken to compute an hdiff for a state",
        &["db"],
    )
});
pub static BEACON_HDIFF_BUFFER_LOAD_TIME: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "store_hdiff_buffer_load_seconds",
        "Time taken to load an hdiff buffer for a state",
        &["db"],
    )
});
pub static BEACON_HDIFF_BUFFER_CLONE_TIME: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "store_hdiff_buffer_clone_seconds",
        "Time taken to clone an hdiff buffer from a cache",
        &["db"],
    )
});
pub static BEACON_HDIFF_BUFFER_LOAD_BEFORE_STORE_TIME: LazyLock<Result<HistogramVec>> =
    LazyLock::new(|| {
        try_create_histogram_vec(
            "store_hdiff_buffer_load_before_store_seconds",
            "Time taken to load the hdiff buffer required for the storage of a new state",
            &["db"],
        )
    });
// This metric is not split hot/cold because it is recorded in a place where that info is not known.
pub static BEACON_HDIFF_BUFFER_APPLY_RESIZES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram_with_buckets(
        "store_hdiff_buffer_apply_resizes",
        "Number of times during diff application that the output buffer had to be resized before decoding succeeded",
        Ok(vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0]),
    )
});
// This metric is not split hot/cold because both databases use the same hierarchy config anyway
// and that's all that affects diff sizes.
pub static BEACON_HDIFF_SIZES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec_with_buckets(
        "store_hdiff_sizes",
        "Size of hdiffs in bytes by layer (exponent)",
        Ok(vec![
            500_000.0,
            2_000_000.0,
            5_000_000.0,
            10_000_000.0,
            15_000_000.0,
            20_000_000.0,
            50_000_000.0,
        ]),
        &["exponent"],
    )
});
/*
 * Beacon Block
 */
pub static BEACON_BLOCK_GET_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "store_beacon_block_get_total",
        "Total number of beacon blocks requested from the store (cache or DB)",
    )
});
pub static BEACON_BLOCK_CACHE_HIT_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "store_beacon_block_cache_hit_total",
        "Number of hits to the store's block cache",
    )
});

/*
 * Caches
 */
pub static BEACON_BLOBS_CACHE_HIT_COUNT: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "store_beacon_blobs_cache_hit_total",
        "Number of hits to the store's blob cache",
    )
});
pub static STORE_BEACON_BLOCK_CACHE_SIZE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_beacon_block_cache_size",
        "Current count of items in beacon store block cache",
    )
});
pub static STORE_BEACON_BLOB_CACHE_SIZE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_beacon_blob_cache_size",
        "Current count of items in beacon store blob cache",
    )
});
pub static STORE_BEACON_STATE_CACHE_SIZE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "store_beacon_state_cache_size",
        "Current count of items in beacon store state cache",
    )
});
pub static STORE_BEACON_HISTORIC_STATE_CACHE_SIZE: LazyLock<Result<IntGauge>> =
    LazyLock::new(|| {
        try_create_int_gauge(
            "store_beacon_historic_state_cache_size",
            "Current count of states in the historic state cache",
        )
    });
pub static STORE_BEACON_HDIFF_BUFFER_CACHE_SIZE: LazyLock<Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "store_beacon_hdiff_buffer_cache_size",
            "Current count of hdiff buffers cached in memory",
            &["db"],
        )
    });
pub static STORE_BEACON_HDIFF_BUFFER_CACHE_BYTE_SIZE: LazyLock<Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "store_beacon_hdiff_buffer_cache_byte_size",
            "Memory consumed by hdiff buffers cached in memory",
            &["db"],
        )
    });
pub static STORE_BEACON_STATE_FREEZER_COMPRESS_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "store_beacon_state_compress_seconds",
            "Time taken to compress a state snapshot for the freezer DB",
        )
    });
pub static STORE_BEACON_STATE_FREEZER_DECOMPRESS_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "store_beacon_state_decompress_seconds",
            "Time taken to decompress a state snapshot for the freezer DB",
        )
    });
pub static STORE_BEACON_HISTORIC_STATE_CACHE_HIT: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| {
        try_create_int_counter(
            "store_beacon_historic_state_cache_hit_total",
            "Total count of historic state cache hits for full states",
        )
    });
pub static STORE_BEACON_HISTORIC_STATE_CACHE_MISS: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| {
        try_create_int_counter(
            "store_beacon_historic_state_cache_miss_total",
            "Total count of historic state cache misses for full states",
        )
    });
pub static STORE_BEACON_HDIFF_BUFFER_CACHE_HIT: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "store_beacon_hdiff_buffer_cache_hit_total",
            "Total count of hdiff buffer cache hits",
            &["db"],
        )
    });
pub static STORE_BEACON_HDIFF_BUFFER_CACHE_MISS: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "store_beacon_hdiff_buffer_cache_miss_total",
            "Total count of hdiff buffer cache miss",
            &["db"],
        )
    });
pub static STORE_BEACON_HDIFF_BUFFER_INTO_STATE_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "store_beacon_hdiff_buffer_into_state_seconds",
            "Time taken to recreate a BeaconState from an hdiff buffer",
        )
    });
pub static STORE_BEACON_HDIFF_BUFFER_FROM_STATE_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "store_beacon_hdiff_buffer_from_state_seconds",
            "Time taken to create an hdiff buffer from a BeaconState",
        )
    });
pub static STORE_BEACON_REPLAYED_BLOCKS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "store_beacon_replayed_blocks_total",
        "Total count of replayed blocks",
    )
});
pub static STORE_BEACON_LOAD_COLD_BLOCKS_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_beacon_load_cold_blocks_time",
        "Time spent loading blocks to replay for historic states",
    )
});
pub static STORE_BEACON_LOAD_HOT_BLOCKS_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_beacon_load_hot_blocks_time",
        "Time spent loading blocks to replay for hot states",
    )
});
pub static STORE_BEACON_REPLAY_COLD_BLOCKS_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "store_beacon_replay_cold_blocks_time",
            "Time spent replaying blocks for historic states",
        )
    });
pub static STORE_BEACON_COLD_BUILD_BEACON_CACHES_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "store_beacon_cold_build_beacon_caches_time",
            "Time spent building caches on historic states",
        )
    });
pub static STORE_BEACON_REPLAY_HOT_BLOCKS_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_beacon_replay_hot_blocks_time",
        "Time spent replaying blocks for hot states",
    )
});
pub static STORE_BEACON_RECONSTRUCTION_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "store_beacon_reconstruction_time_seconds",
        "Time taken to run a reconstruct historic states batch",
    )
});
pub static BEACON_DATA_COLUMNS_CACHE_HIT_COUNT: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| {
        try_create_int_counter(
            "store_beacon_data_columns_cache_hit_total",
            "Number of hits to the store's data column cache",
        )
    });

/// Updates the global metrics registry with store-related information.
pub fn scrape_for_metrics(db_path: &Path, freezer_db_path: &Path) {
    let db_size = size_of_dir(db_path);
    set_gauge(&DISK_DB_SIZE, db_size as i64);
    let freezer_db_size = size_of_dir(freezer_db_path);
    set_gauge(&FREEZER_DB_SIZE, freezer_db_size as i64);
}
