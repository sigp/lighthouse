use beacon_chain::attestation_verification::Error as AttnError;
pub use lighthouse_metrics::*;

lazy_static! {
    /*
     * Gossip Rx
     */
    pub static ref GOSSIP_BLOCKS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_blocks_rx_total",
        "Count of gossip blocks received"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_unaggregated_attestations_rx_total",
        "Count of gossip unaggregated attestations received"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_aggregated_attestations_rx_total",
        "Count of gossip aggregated attestations received"
    );

    /*
     * Gossip Tx
     */
    pub static ref GOSSIP_BLOCKS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_blocks_tx_total",
        "Count of gossip blocks transmitted"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_unaggregated_attestations_tx_total",
        "Count of gossip unaggregated attestations transmitted"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_aggregated_attestations_tx_total",
        "Count of gossip aggregated attestations transmitted"
    );

    /*
     * Attestation subnet subscriptions
     */
    pub static ref SUBNET_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "network_subnet_subscriptions_total",
        "Count of validator subscription requests."
    );
    pub static ref SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "network_subnet_subscriptions_aggregator_total",
        "Count of validator subscription requests where the subscriber is an aggregator."
    );

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
    pub static ref BEACON_PROCESSOR_CHAIN_SEGMENT_SUCCESS_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_chain_segment_success_total",
        "Total number of chain segments successfully processed."
    );
    pub static ref BEACON_PROCESSOR_CHAIN_SEGMENT_FAILED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_chain_segment_failed_total",
        "Total number of chain segments that failed processing."
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

    /*
     * Attestation Errors
     */
    pub static ref GOSSIP_ATTESTATION_ERROR_FUTURE_EPOCH: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_future_epoch",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_PAST_EPOCH: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_past_epoch",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_FUTURE_SLOT: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_future_slot",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_PAST_SLOT: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_past_slot",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_SELECTION_PROOF: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_invalid_selection_proof",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_SIGNATURE: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_invalid_signature",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_EMPTY_AGGREGATION_BITFIELD: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_empty_aggregation_bitfield",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_AGGREGATOR_PUBKEY_UNKNOWN: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_aggregator_pubkey_unknown",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_AGGREGATOR_NOT_IN_COMMITTEE: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_aggregator_not_in_committee",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_ATTESTATION_ALREADY_KNOWN: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_attestation_already_known",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_AGGREGATOR_ALREADY_KNOWN: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_aggregator_already_known",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_PRIOR_ATTESTATION_KNOWN: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_prior_attestation_known",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_VALIDATOR_INDEX_TOO_HIGH: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_validator_index_too_high",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_UNKNOWN_HEAD_BLOCK: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_unknown_head_block",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_UNKNOWN_TARGET_ROOT: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_unknown_target_root",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_BAD_TARGET_EPOCH: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_bad_target_epoch",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_NO_COMMITTEE_FOR_SLOT_AND_INDEX: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_no_committee_for_slot_and_index",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_NOT_EXACTLY_ONE_AGGREGATION_BIT_SET: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_not_exactly_one_aggregation_bit_set",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_ATTESTS_TO_FUTURE_BLOCK: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_attests_to_future_block",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_SUBNET_ID: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_invalid_subnet_id",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_STATE_PROCESSING: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_invalid_state_processing",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_BEACON_CHAIN_ERROR: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_beacon_chain_error",
        "Count of a specific error type (see metric name)"
    );
}

pub fn register_attestation_error(error: &AttnError) {
    match error {
        AttnError::FutureEpoch { .. } => inc_counter(&GOSSIP_ATTESTATION_ERROR_FUTURE_EPOCH),
        AttnError::PastEpoch { .. } => inc_counter(&GOSSIP_ATTESTATION_ERROR_PAST_EPOCH),
        AttnError::FutureSlot { .. } => inc_counter(&GOSSIP_ATTESTATION_ERROR_FUTURE_SLOT),
        AttnError::PastSlot { .. } => inc_counter(&GOSSIP_ATTESTATION_ERROR_PAST_SLOT),
        AttnError::InvalidSelectionProof { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_INVALID_SELECTION_PROOF)
        }
        AttnError::InvalidSignature => inc_counter(&GOSSIP_ATTESTATION_ERROR_INVALID_SIGNATURE),
        AttnError::EmptyAggregationBitfield => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_EMPTY_AGGREGATION_BITFIELD)
        }
        AttnError::AggregatorPubkeyUnknown(_) => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_AGGREGATOR_PUBKEY_UNKNOWN)
        }
        AttnError::AggregatorNotInCommittee { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_AGGREGATOR_NOT_IN_COMMITTEE)
        }
        AttnError::AttestationAlreadyKnown { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_ATTESTATION_ALREADY_KNOWN)
        }
        AttnError::AggregatorAlreadyKnown(_) => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_AGGREGATOR_ALREADY_KNOWN)
        }
        AttnError::PriorAttestationKnown { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_PRIOR_ATTESTATION_KNOWN)
        }
        AttnError::ValidatorIndexTooHigh(_) => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_VALIDATOR_INDEX_TOO_HIGH)
        }
        AttnError::UnknownHeadBlock { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_UNKNOWN_HEAD_BLOCK)
        }
        AttnError::UnknownTargetRoot(_) => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_UNKNOWN_TARGET_ROOT)
        }
        AttnError::BadTargetEpoch => inc_counter(&GOSSIP_ATTESTATION_ERROR_BAD_TARGET_EPOCH),
        AttnError::NoCommitteeForSlotAndIndex { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_NO_COMMITTEE_FOR_SLOT_AND_INDEX)
        }
        AttnError::NotExactlyOneAggregationBitSet(_) => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_NOT_EXACTLY_ONE_AGGREGATION_BIT_SET)
        }
        AttnError::AttestsToFutureBlock { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_ATTESTS_TO_FUTURE_BLOCK)
        }
        AttnError::InvalidSubnetId { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_INVALID_SUBNET_ID)
        }
        AttnError::Invalid(_) => inc_counter(&GOSSIP_ATTESTATION_ERROR_INVALID_STATE_PROCESSING),
        AttnError::BeaconChainError(_) => inc_counter(&GOSSIP_ATTESTATION_ERROR_BEACON_CHAIN_ERROR),
    }
}
