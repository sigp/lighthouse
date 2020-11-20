use beacon_chain::attestation_verification::Error as AttnError;
pub use lighthouse_metrics::*;

lazy_static! {

    /*
     * Gossip subnets and scoring
     */
    pub static ref PEERS_PER_PROTOCOL: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_peers_per_protocol",
        "Peers via supported protocol",
        &["protocol"]
    );

    pub static ref GOSSIPSUB_SUBSCRIBED_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_subscribed_subnets",
        "Subnets currently subscribed to",
        &["subnet"]
    );

    pub static ref GOSSIPSUB_SUBSCRIBED_PEERS_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_peers_per_subnet_topic_count",
        "Peers subscribed per subnet topic",
        &["subnet"]
    );

    pub static ref MESH_PEERS_PER_MAIN_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_mesh_peers_per_main_topic",
        "Mesh peers per main topic",
        &["topic_hash"]
    );

    pub static ref MESH_PEERS_PER_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_mesh_peers_per_subnet_topic",
        "Mesh peers per subnet topic",
        &["subnet"]
    );

    pub static ref AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_avg_peer_score_per_topic",
        "Average peer's score per topic",
        &["topic_hash"]
    );

    pub static ref AVG_GOSSIPSUB_PEER_SCORE_PER_SUBNET_TOPIC: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_avg_peer_score_per_subnet_topic",
        "Average peer's score per subnet topic",
        &["subnet"]
    );

    pub static ref ATTESTATIONS_PUBLISHED_PER_SUBNET_PER_SLOT: Result<IntCounterVec> = try_create_int_counter_vec(
        "gossipsub_attestations_published_per_subnet_per_slot",
        "Failed attestation publishes per subnet",
        &["subnet"]
    );

    pub static ref SCORES_BELOW_ZERO_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_scores_below_zero_per_client",
        "Relative number of scores below zero per client",
        &["Client"]
    );
    pub static ref SCORES_BELOW_GOSSIP_THRESHOLD_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_scores_below_gossip_threshold_per_client",
        "Relative number of scores below gossip threshold per client",
        &["Client"]
    );
    pub static ref SCORES_BELOW_PUBLISH_THRESHOLD_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_scores_below_publish_threshold_per_client",
        "Relative number of scores below publish threshold per client",
        &["Client"]
    );
    pub static ref SCORES_BELOW_GREYLIST_THRESHOLD_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_scores_below_greylist_threshold_per_client",
        "Relative number of scores below greylist threshold per client",
        &["Client"]
    );

    pub static ref MIN_SCORES_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_min_scores_per_client",
        "Minimum scores per client",
        &["Client"]
    );
    pub static ref MEDIAN_SCORES_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_median_scores_per_client",
        "Median scores per client",
        &["Client"]
    );
    pub static ref MEAN_SCORES_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_mean_scores_per_client",
        "Mean scores per client",
        &["Client"]
    );
    pub static ref MAX_SCORES_PER_CLIENT: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_max_scores_per_client",
        "Max scores per client",
        &["Client"]
    );
    pub static ref BEACON_BLOCK_MESH_PEERS_PER_CLIENT: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "block_mesh_peers_per_client",
            "Number of mesh peers for BeaconBlock topic per client",
            &["Client"]
        );
    pub static ref BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "beacon_aggregate_and_proof_mesh_peers_per_client",
            "Number of mesh peers for BeaconAggregateAndProof topic per client",
            &["Client"]
        );
}

lazy_static! {
    /*
     * Gossip Rx
     */
    pub static ref GOSSIP_BLOCKS_RX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_blocks_rx_total",
        "Count of gossip blocks received"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_unaggregated_attestations_rx_total",
        "Count of gossip unaggregated attestations received"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_aggregated_attestations_rx_total",
        "Count of gossip aggregated attestations received"
    );


    /*
     * Gossip Tx
     */
    pub static ref GOSSIP_BLOCKS_TX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_blocks_tx_total",
        "Count of gossip blocks transmitted"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_unaggregated_attestations_tx_total",
        "Count of gossip unaggregated attestations transmitted"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_aggregated_attestations_tx_total",
        "Count of gossip aggregated attestations transmitted"
    );

    /*
     * Attestation subnet subscriptions
     */
    pub static ref SUBNET_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "gossipsub_subnet_subscriptions_total",
        "Count of validator subscription requests."
    );
    pub static ref SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "gossipsub_subnet_subscriptions_aggregator_total",
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
    pub static ref BEACON_PROCESSOR_ATTESTER_SLASHING_ERROR_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_attester_slashing_error_total",
        "Total number of attester slashings that raised an error during processing."
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
}

lazy_static! {
    /*
     * Attestation Errors
     */
    pub static ref GOSSIP_ATTESTATION_ERROR_FUTURE_EPOCH: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_future_epoch",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_PAST_EPOCH: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_past_epoch",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_FUTURE_SLOT: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_future_slot",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_PAST_SLOT: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_past_slot",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_SELECTION_PROOF: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_invalid_selection_proof",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_SIGNATURE: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_invalid_signature",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_EMPTY_AGGREGATION_BITFIELD: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_empty_aggregation_bitfield",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_AGGREGATOR_PUBKEY_UNKNOWN: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_aggregator_pubkey_unknown",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_AGGREGATOR_NOT_IN_COMMITTEE: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_aggregator_not_in_committee",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_ATTESTATION_ALREADY_KNOWN: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_attestation_already_known",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_AGGREGATOR_ALREADY_KNOWN: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_aggregator_already_known",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_PRIOR_ATTESTATION_KNOWN: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_prior_attestation_known",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_VALIDATOR_INDEX_TOO_HIGH: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_validator_index_too_high",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_UNKNOWN_HEAD_BLOCK: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_unknown_head_block",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_UNKNOWN_TARGET_ROOT: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_unknown_target_root",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_BAD_TARGET_EPOCH: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_bad_target_epoch",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_NO_COMMITTEE_FOR_SLOT_AND_INDEX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_no_committee_for_slot_and_index",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_NOT_EXACTLY_ONE_AGGREGATION_BIT_SET: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_not_exactly_one_aggregation_bit_set",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_ATTESTS_TO_FUTURE_BLOCK: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_attests_to_future_block",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_SUBNET_ID: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_invalid_subnet_id",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_STATE_PROCESSING: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_invalid_state_processing",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_TOO_MANY_SKIPPED_SLOTS: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_invalid_too_many_skipped_slots",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_TARGET_ROOT: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_invalid_target_root",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_INVALID_TARGET_EPOCH: Result<IntCounter> = try_create_int_counter(
        "gossip_attestation_error_invalid_target_epoch",
        "Count of a specific error type (see metric name)"
    );
    pub static ref GOSSIP_ATTESTATION_ERROR_BEACON_CHAIN_ERROR: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_error_beacon_chain_error",
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
        AttnError::InvalidTargetRoot { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_INVALID_TARGET_ROOT)
        }
        AttnError::InvalidTargetEpoch { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_INVALID_TARGET_EPOCH)
        }
        AttnError::TooManySkippedSlots { .. } => {
            inc_counter(&GOSSIP_ATTESTATION_ERROR_INVALID_TOO_MANY_SKIPPED_SLOTS)
        }
        AttnError::BeaconChainError(_) => inc_counter(&GOSSIP_ATTESTATION_ERROR_BEACON_CHAIN_ERROR),
    }
}
