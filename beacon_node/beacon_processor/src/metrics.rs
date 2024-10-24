pub use metrics::*;
use std::sync::LazyLock;

/*
 * Gossip processor
 */
pub static BEACON_PROCESSOR_WORK_EVENTS_RX_COUNT: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "beacon_processor_work_events_rx_count",
            "Count of work events received (but not necessarily processed)",
            &["type"],
        )
    });
pub static BEACON_PROCESSOR_WORK_EVENTS_IGNORED_COUNT: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "beacon_processor_work_events_ignored_count",
            "Count of work events purposefully ignored",
            &["type"],
        )
    });
pub static BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "beacon_processor_work_events_started_count",
            "Count of work events which have been started by a worker",
            &["type"],
        )
    });
pub static BEACON_PROCESSOR_WORKER_TIME: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "beacon_processor_worker_time",
        "Time taken for a worker to fully process some parcel of work.",
        &["type"],
    )
});
pub static BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| {
        try_create_int_counter(
            "beacon_processor_workers_spawned_total",
            "The number of workers ever spawned by the gossip processing pool.",
        )
    });
pub static BEACON_PROCESSOR_WORKERS_ACTIVE_TOTAL: LazyLock<Result<IntGauge>> =
    LazyLock::new(|| {
        try_create_int_gauge(
            "beacon_processor_workers_active_total",
            "Count of active workers in the gossip processing pool.",
        )
    });
pub static BEACON_PROCESSOR_IDLE_EVENTS_TOTAL: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_processor_idle_events_total",
        "Count of idle events processed by the gossip processor manager.",
    )
});
pub static BEACON_PROCESSOR_EVENT_HANDLING_SECONDS: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "beacon_processor_event_handling_seconds",
            "Time spent handling a new message and allocating it to a queue or worker.",
        )
    });
pub static BEACON_PROCESSOR_QUEUE_LENGTH: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec_with_buckets(
        "beacon_processor_work_event_queue_length",
        "Count of work events in queue waiting to be processed.",
        Ok(vec![
            0.0, 1.0, 4.0, 16.0, 64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0,
        ]),
        &["type"],
    )
});

/*
 * Attestation reprocessing queue metrics.
 */
pub static BEACON_PROCESSOR_REPROCESSING_QUEUE_TOTAL: LazyLock<Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "beacon_processor_reprocessing_queue_total",
            "Count of items in a reprocessing queue.",
            &["type"],
        )
    });
pub static BEACON_PROCESSOR_REPROCESSING_QUEUE_EXPIRED_ATTESTATIONS: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| {
        try_create_int_counter(
        "beacon_processor_reprocessing_queue_expired_attestations",
        "Number of queued attestations which have expired before a matching block has been found."
    )
    });
pub static BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_ATTESTATIONS: LazyLock<Result<IntCounter>> =
    LazyLock::new(|| {
        try_create_int_counter(
            "beacon_processor_reprocessing_queue_matched_attestations",
            "Number of queued attestations where as matching block has been imported.",
        )
    });
// TODO: This should be labeled instead of N single metrics
pub static BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_SAMPLING_REQUESTS: LazyLock<
    Result<IntCounter>,
> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_processor_reprocessing_queue_matched_sampling_requests",
        "Number of queued sampling requests where a matching block has been imported.",
    )
});

/*
 * Light client update reprocessing queue metrics.
 */
pub static BEACON_PROCESSOR_REPROCESSING_QUEUE_EXPIRED_OPTIMISTIC_UPDATES: LazyLock<
    Result<IntCounter>,
> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_processor_reprocessing_queue_expired_optimistic_updates",
        "Number of queued light client optimistic updates which have expired before a matching block has been found."
    )
});
pub static BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_OPTIMISTIC_UPDATES: LazyLock<
    Result<IntCounter>,
> = LazyLock::new(|| {
    try_create_int_counter(
        "beacon_processor_reprocessing_queue_matched_optimistic_updates",
        "Number of queued light client optimistic updates where a matching block has been imported."
    )
});

/// Errors and Debugging Stats
pub static BEACON_PROCESSOR_SEND_ERROR_PER_WORK_TYPE: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "beacon_processor_send_error_per_work_type",
            "Total number of beacon processor send error per work type",
            &["type"],
        )
    });
