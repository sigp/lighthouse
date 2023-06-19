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
    pub static ref BEACON_PROCESSOR_GOSSIP_BLOCK_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_gossip_block_verified_total",
        "Total number of gossip blocks verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_GOSSIP_BLOCK_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_gossip_block_imported_total",
        "Total number of gossip blocks imported to fork choice, etc."
    );
    pub static ref BEACON_PROCESSOR_GOSSIP_BLOCK_REQUEUED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_gossip_block_requeued_total",
        "Total number of gossip blocks that arrived early and were re-queued for later processing."
    );
    pub static ref BEACON_PROCESSOR_GOSSIP_BLOCK_EARLY_SECONDS: Result<Histogram> = try_create_histogram(
        "beacon_processor_gossip_block_early_seconds",
        "Whenever a gossip block is received early this metrics is set to how early that block was."
    );
    // Gossip Exits.
    pub static ref BEACON_PROCESSOR_EXIT_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_exit_queue_total",
        "Count of exits from gossip waiting to be verified."
    );
    pub static ref BEACON_PROCESSOR_EXIT_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_exit_verified_total",
        "Total number of voluntary exits verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_EXIT_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_exit_imported_total",
        "Total number of voluntary exits imported to the op pool."
    );
    // Gossip proposer slashings.
    pub static ref BEACON_PROCESSOR_PROPOSER_SLASHING_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_proposer_slashing_queue_total",
        "Count of proposer slashings from gossip waiting to be verified."
    );
    pub static ref BEACON_PROCESSOR_PROPOSER_SLASHING_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_proposer_slashing_verified_total",
        "Total number of proposer slashings verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_PROPOSER_SLASHING_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_proposer_slashing_imported_total",
        "Total number of proposer slashings imported to the op pool."
    );
    // Gossip attester slashings.
    pub static ref BEACON_PROCESSOR_ATTESTER_SLASHING_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_attester_slashing_queue_total",
        "Count of attester slashings from gossip waiting to be verified."
    );
    pub static ref BEACON_PROCESSOR_ATTESTER_SLASHING_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_attester_slashing_verified_total",
        "Total number of attester slashings verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_ATTESTER_SLASHING_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_attester_slashing_imported_total",
        "Total number of attester slashings imported to the op pool."
    );
    // Gossip BLS to execution changes.
    pub static ref BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_bls_to_execution_change_queue_total",
        "Count of address changes from gossip waiting to be verified."
    );
    pub static ref BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_bls_to_execution_change_verified_total",
        "Total number of address changes verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_bls_to_execution_change_imported_total",
        "Total number of address changes imported to the op pool."
    );
    // Rpc blocks.
    pub static ref BEACON_PROCESSOR_RPC_BLOCK_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_rpc_block_queue_total",
        "Count of blocks from the rpc waiting to be verified."
    );
    pub static ref BEACON_PROCESSOR_RPC_BLOCK_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_rpc_block_imported_total",
        "Total number of gossip blocks imported to fork choice, etc."
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
    pub static ref BEACON_PROCESSOR_CHAIN_SEGMENT_SUCCESS_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_chain_segment_success_total",
        "Total number of chain segments successfully processed."
    );
    pub static ref BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_SUCCESS_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_backfill_chain_segment_success_total",
        "Total number of chain segments successfully processed."
    );
    pub static ref BEACON_PROCESSOR_CHAIN_SEGMENT_FAILED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_chain_segment_failed_total",
        "Total number of chain segments that failed processing."
    );
    pub static ref BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_FAILED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_backfill_chain_segment_failed_total",
        "Total number of backfill chain segments that failed processing."
    );
    // Unaggregated attestations.
    pub static ref BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_unaggregated_attestation_queue_total",
        "Count of unagg. attestations waiting to be processed."
    );
    pub static ref BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_unaggregated_attestation_verified_total",
        "Total number of unaggregated attestations verified for gossip."
    );
    pub static ref BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_unaggregated_attestation_imported_total",
        "Total number of unaggregated attestations imported to fork choice, etc."
    );
    pub static ref BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_REQUEUED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_unaggregated_attestation_requeued_total",
        "Total number of unaggregated attestations that referenced an unknown block and were re-queued."
    );
    // Aggregated attestations.
    pub static ref BEACON_PROCESSOR_AGGREGATED_ATTESTATION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_aggregated_attestation_queue_total",
        "Count of agg. attestations waiting to be processed."
    );
    pub static ref BEACON_PROCESSOR_AGGREGATED_ATTESTATION_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_aggregated_attestation_verified_total",
        "Total number of aggregated attestations verified for gossip."
    );
    pub static ref BEACON_PROCESSOR_AGGREGATED_ATTESTATION_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_aggregated_attestation_imported_total",
        "Total number of aggregated attestations imported to fork choice, etc."
    );
    pub static ref BEACON_PROCESSOR_AGGREGATED_ATTESTATION_REQUEUED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_aggregated_attestation_requeued_total",
        "Total number of aggregated attestations that referenced an unknown block and were re-queued."
    );
    // Sync committee messages.
    pub static ref BEACON_PROCESSOR_SYNC_MESSAGE_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_sync_message_queue_total",
        "Count of sync committee messages waiting to be processed."
    );
    pub static ref BEACON_PROCESSOR_SYNC_MESSAGE_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_message_verified_total",
        "Total number of sync committee messages verified for gossip."
    );
    pub static ref BEACON_PROCESSOR_SYNC_MESSAGE_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_message_imported_total",
        "Total number of sync committee messages imported to fork choice, etc."
    );
    // Sync contribution.
    pub static ref BEACON_PROCESSOR_SYNC_CONTRIBUTION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "beacon_processor_sync_contribution_queue_total",
        "Count of sync committee contributions waiting to be processed."
    );
    pub static ref BEACON_PROCESSOR_SYNC_CONTRIBUTION_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_contribution_verified_total",
        "Total number of sync committee contributions verified for gossip."
    );

    pub static ref BEACON_PROCESSOR_SYNC_CONTRIBUTION_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_contribution_imported_total",
        "Total number of sync committee contributions imported to fork choice, etc."
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
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_SENT_OPTIMISTIC_UPDATES: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_reprocessing_queue_sent_optimistic_updates",
        "Number of queued light client optimistic updates where as matching block has been imported."
    );

    /*
     * Block Delay Metrics
     */
    pub static ref BEACON_BLOCK_GOSSIP_PROPAGATION_VERIFICATION_DELAY_TIME: Result<Histogram> = try_create_histogram_with_buckets(
        "beacon_block_gossip_propagation_verification_delay_time",
        "Duration between when the block is received and when it is verified for propagation.",
        // [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5]
        decimal_buckets(-3,-1)
    );
    pub static ref BEACON_BLOCK_GOSSIP_SLOT_START_DELAY_TIME: Result<Histogram> = try_create_histogram_with_buckets(
        "beacon_block_gossip_slot_start_delay_time",
        "Duration between when the block is received and the start of the slot it belongs to.",
        // Create a custom bucket list for greater granularity in block delay
        Ok(vec![0.1, 0.2, 0.3,0.4,0.5,0.75,1.0,1.25,1.5,1.75,2.0,2.5,3.0,3.5,4.0,5.0,6.0,7.0,8.0,9.0,10.0,15.0,20.0])
        // NOTE: Previous values, which we may want to switch back to.
        // [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50]
        //decimal_buckets(-1,2)

    );
    pub static ref BEACON_BLOCK_LAST_DELAY: Result<IntGauge> = try_create_int_gauge(
        "beacon_block_last_delay",
        "Keeps track of the last block's delay from the start of the slot"
    );

    pub static ref BEACON_BLOCK_GOSSIP_ARRIVED_LATE_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_block_gossip_arrived_late_total",
        "Count of times when a gossip block arrived from the network later than the attestation deadline.",
    );

    /// Errors and Debugging Stats
    pub static ref GOSSIP_ATTESTATION_ERRORS_PER_TYPE: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_attestation_errors_per_type",
            "Gossipsub attestation errors per error type",
            &["type"]
        );
    pub static ref GOSSIP_SYNC_COMMITTEE_ERRORS_PER_TYPE: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_sync_committee_errors_per_type",
            "Gossipsub sync_committee errors per error type",
            &["type"]
        );
    pub static ref GOSSIP_FINALITY_UPDATE_ERRORS_PER_TYPE: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_light_client_finality_update_errors_per_type",
            "Gossipsub light_client_finality_update errors per error type",
            &["type"]
        );
    pub static ref GOSSIP_OPTIMISTIC_UPDATE_ERRORS_PER_TYPE: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_light_client_optimistic_update_errors_per_type",
            "Gossipsub light_client_optimistic_update errors per error type",
            &["type"]
        );
}

pub fn register_finality_update_error(error: &impl AsRef<str>) {
    inc_counter_vec(&GOSSIP_FINALITY_UPDATE_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn register_optimistic_update_error(error: &impl AsRef<str>) {
    inc_counter_vec(&GOSSIP_OPTIMISTIC_UPDATE_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn register_attestation_error(error: &impl AsRef<str>) {
    inc_counter_vec(&GOSSIP_ATTESTATION_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn register_sync_committee_error(error: &impl AsRef<str>) {
    inc_counter_vec(&GOSSIP_SYNC_COMMITTEE_ERRORS_PER_TYPE, &[error.as_ref()]);
}
