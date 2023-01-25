use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref SLASHER_DATABASE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "slasher_database_size",
        "Size of the database backing the slasher, in bytes"
    );
    pub static ref SLASHER_RUN_TIME: Result<Histogram> = try_create_histogram(
        "slasher_process_batch_time",
        "Time taken to process a batch of blocks and attestations"
    );
    pub static ref SLASHER_NUM_ATTESTATIONS_DROPPED: Result<IntGauge> = try_create_int_gauge(
        "slasher_num_attestations_dropped",
        "Number of attestations dropped per batch"
    );
    pub static ref SLASHER_NUM_ATTESTATIONS_DEFERRED: Result<IntGauge> = try_create_int_gauge(
        "slasher_num_attestations_deferred",
        "Number of attestations deferred per batch"
    );
    pub static ref SLASHER_NUM_ATTESTATIONS_VALID: Result<IntGauge> = try_create_int_gauge(
        "slasher_num_attestations_valid",
        "Number of valid attestations per batch"
    );
    pub static ref SLASHER_NUM_ATTESTATIONS_STORED_PER_BATCH: Result<IntGauge> =
        try_create_int_gauge(
            "slasher_num_attestations_stored_per_batch",
            "Number of attestations stored per batch"
        );
    pub static ref SLASHER_NUM_BLOCKS_PROCESSED: Result<IntGauge> = try_create_int_gauge(
        "slasher_num_blocks_processed",
        "Number of blocks processed per batch",
    );
    pub static ref SLASHER_NUM_CHUNKS_UPDATED: Result<IntCounterVec> = try_create_int_counter_vec(
        "slasher_num_chunks_updated",
        "Number of min or max target chunks updated on disk",
        &["array"],
    );
    pub static ref SLASHER_COMPRESSION_RATIO: Result<Gauge> = try_create_float_gauge(
        "slasher_compression_ratio",
        "Compression ratio for min-max array chunks (higher is better)"
    );
    pub static ref SLASHER_NUM_ATTESTATION_ROOT_QUERIES: Result<IntCounter> =
        try_create_int_counter(
            "slasher_num_attestation_root_queries",
            "Number of requests for an attestation data root",
        );
    pub static ref SLASHER_NUM_ATTESTATION_ROOT_HITS: Result<IntCounter> = try_create_int_counter(
        "slasher_num_attestation_root_hits",
        "Number of requests for an attestation data root that hit the LRU cache",
    );
    pub static ref SLASHER_ATTESTATION_ROOT_CACHE_SIZE: Result<IntGauge> = try_create_int_gauge(
        "slasher_attestation_root_cache_size",
        "Number of attestation data roots cached in memory"
    );
}
