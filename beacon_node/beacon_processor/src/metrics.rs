pub use lighthouse_metrics::*;

lazy_static::lazy_static! {

    /*
     * Gossip processor
     */
    pub static ref BEACON_PROCESSOR_WORK_EVENTS_RX_COUNT: Result<IntCounterVec> = try_create_int_counter_vec(
        "beacon_processor_work_events_rx_count",
        "Count of work events received (but not necessarily processed)",
        &["type"]
    );
    pub static ref BEACON_PROCESSOR_WORK_EVENTS_IGNORED_COUNT: Result<IntCounterVec> = try_create_int_counter_vec(
        "beacon_processor_work_events_ignored_count",
        "Count of work events purposefully ignored",
        &["type"]
    );
    pub static ref BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT: Result<IntCounterVec> = try_create_int_counter_vec(
        "beacon_processor_work_events_started_count",
        "Count of work events which have been started by a worker",
        &["type"]
    );
    pub static ref BEACON_PROCESSOR_WORKER_TIME: Result<HistogramVec> = try_create_histogram_vec(
        "beacon_processor_worker_time",
        "Time taken for a worker to fully process some parcel of work.",
        &["type"]
    );
    pub static ref BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_workers_spawned_total",
        "The number of workers ever spawned by the gossip processing pool."
    );
    pub static ref BEACON_PROCESSOR_WORKERS_ACTIVE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_workers_active_total",
        "Count of active workers in the gossip processing pool."
    );
    pub static ref BEACON_PROCESSOR_IDLE_EVENTS_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_idle_events_total",
        "Count of idle events processed by the gossip processor manager."
    );
    pub static ref BEACON_PROCESSOR_EVENT_HANDLING_SECONDS: Result<Histogram> = try_create_histogram(
        "beacon_processor_event_handling_seconds",
        "Time spent handling a new message and allocating it to a queue or worker."
    );
    // Gossip blocks.
    pub static ref BEACON_PROCESSOR_GOSSIP_BLOCK_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_gossip_block_queue_total",
        "Count of blocks from gossip waiting to be verified."
    );
    // Gossip Exits.
    pub static ref BEACON_PROCESSOR_EXIT_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_exit_queue_total",
        "Count of exits from gossip waiting to be verified."
    );
    // Gossip proposer slashings.
    pub static ref BEACON_PROCESSOR_PROPOSER_SLASHING_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_proposer_slashing_queue_total",
        "Count of proposer slashings from gossip waiting to be verified."
    );
    // Gossip attester slashings.
    pub static ref BEACON_PROCESSOR_ATTESTER_SLASHING_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_attester_slashing_queue_total",
        "Count of attester slashings from gossip waiting to be verified."
    );
    // Gossip BLS to execution changes.
    pub static ref BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_bls_to_execution_change_queue_total",
        "Count of address changes from gossip waiting to be verified."
    );
    // Rpc blocks.
    pub static ref BEACON_PROCESSOR_RPC_BLOCK_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_rpc_block_queue_total",
        "Count of blocks from the rpc waiting to be verified."
    );
    // Chain segments.
    pub static ref BEACON_PROCESSOR_CHAIN_SEGMENT_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_chain_segment_queue_total",
        "Count of chain segments from the rpc waiting to be verified."
    );
    pub static ref BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_backfill_chain_segment_queue_total",
        "Count of backfill chain segments from the rpc waiting to be verified."
    );
    // Unaggregated attestations.
    pub static ref BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_unaggregated_attestation_queue_total",
        "Count of unagg. attestations waiting to be processed."
    );
    // Aggregated attestations.
    pub static ref BEACON_PROCESSOR_AGGREGATED_ATTESTATION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_aggregated_attestation_queue_total",
        "Count of agg. attestations waiting to be processed."
    );
    // Sync committee messages.
    pub static ref BEACON_PROCESSOR_SYNC_MESSAGE_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_sync_message_queue_total",
        "Count of sync committee messages waiting to be processed."
    );
    // Sync contribution.
    pub static ref BEACON_PROCESSOR_SYNC_CONTRIBUTION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_sync_contribution_queue_total",
        "Count of sync committee contributions waiting to be processed."
    );
    // HTTP API requests.
    pub static ref BEACON_PROCESSOR_API_REQUEST_P0_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_api_request_p0_queue_total",
        "Count of P0 HTTP requesets waiting to be processed."
    );
    pub static ref BEACON_PROCESSOR_API_REQUEST_P1_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_api_request_p1_queue_total",
        "Count of P1 HTTP requesets waiting to be processed."
    );

    /*
     * Attestation reprocessing queue metrics.
     */
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_TOTAL: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
        "beacon_processor_reprocessing_queue_total",
        "Count of items in a reprocessing queue.",
        &["type"]
    );
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_EXPIRED_ATTESTATIONS: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_reprocessing_queue_expired_attestations",
        "Number of queued attestations which have expired before a matching block has been found."
    );
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_ATTESTATIONS: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_reprocessing_queue_matched_attestations",
        "Number of queued attestations where as matching block has been imported."
    );

    /*
     * Light client update reprocessing queue metrics.
     */
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_EXPIRED_OPTIMISTIC_UPDATES: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_reprocessing_queue_expired_optimistic_updates",
        "Number of queued light client optimistic updates which have expired before a matching block has been found."
    );
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_OPTIMISTIC_UPDATES: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_reprocessing_queue_matched_optimistic_updates",
        "Number of queued light client optimistic updates where as matching block has been imported."
    );

    /// Errors and Debugging Stats
    pub static ref BEACON_PROCESSOR_SEND_ERROR_PER_WORK_TYPE: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "beacon_processor_send_error_per_work_type",
            "Total number of beacon processor send error per work type",
            &["type"]
        );
}
