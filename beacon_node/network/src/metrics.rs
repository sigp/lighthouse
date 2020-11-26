use beacon_chain::attestation_verification::Error as AttnError;
use eth2_libp2p::PubsubMessage;
use eth2_libp2p::{
    types::GossipKind, BandwidthSinks, GossipTopic, Gossipsub, NetworkGlobals, TopicHash,
};
use fnv::FnvHashMap;
pub use lighthouse_metrics::*;
use std::{collections::HashMap, sync::Arc};
use types::{subnet_id::subnet_id_to_string, EthSpec};

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

    pub static ref INBOUND_LIBP2P_BYTES: Result<IntGauge> =
        try_create_int_gauge("libp2p_inbound_bytes", "The inbound bandwidth over libp2p");

    pub static ref OUTBOUND_LIBP2P_BYTES: Result<IntGauge> = try_create_int_gauge(
        "libp2p_outbound_bytes",
        "The outbound bandwidth over libp2p"
    );
    pub static ref TOTAL_LIBP2P_BANDWIDTH: Result<IntGauge> = try_create_int_gauge(
        "libp2p_total_bandwidth",
        "The total inbound/outbound bandwidth over libp2p"
    );
}

pub fn update_bandwidth_metrics(bandwidth: Arc<BandwidthSinks>) {
    set_gauge(&INBOUND_LIBP2P_BYTES, bandwidth.total_inbound() as i64);
    set_gauge(&OUTBOUND_LIBP2P_BYTES, bandwidth.total_outbound() as i64);
    set_gauge(
        &TOTAL_LIBP2P_BANDWIDTH,
        (bandwidth.total_inbound() + bandwidth.total_outbound()) as i64,
    );
}

lazy_static! {
    /*
     * Sync related metrics
     */
    pub static ref PEERS_PER_SYNC_TYPE: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "sync_peers_per_status",
        "Number of connected peers per sync status type",
        &["sync_status"]
    );
    pub static ref SYNCING_CHAINS_COUNT: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "sync_range_chains",
        "Number of Syncing chains in range, per range type",
        &["range_type"]
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

/// Inspects the `messages` that were being sent to the network and updates Prometheus metrics.
pub fn expose_publish_metrics<T: EthSpec>(messages: &[PubsubMessage<T>]) {
    for message in messages {
        match message {
            PubsubMessage::BeaconBlock(_) => inc_counter(&GOSSIP_BLOCKS_TX),
            PubsubMessage::Attestation(subnet_id) => {
                inc_counter_vec(
                    &ATTESTATIONS_PUBLISHED_PER_SUBNET_PER_SLOT,
                    &[&subnet_id.0.as_ref()],
                );
                inc_counter(&GOSSIP_UNAGGREGATED_ATTESTATIONS_TX)
            }
            PubsubMessage::AggregateAndProofAttestation(_) => {
                inc_counter(&GOSSIP_AGGREGATED_ATTESTATIONS_TX)
            }
            _ => {}
        }
    }
}

/// Inspects a `message` received from the network and updates Prometheus metrics.
pub fn expose_receive_metrics<T: EthSpec>(message: &PubsubMessage<T>) {
    match message {
        PubsubMessage::BeaconBlock(_) => inc_counter(&GOSSIP_BLOCKS_RX),
        PubsubMessage::Attestation(_) => inc_counter(&GOSSIP_UNAGGREGATED_ATTESTATIONS_RX),
        PubsubMessage::AggregateAndProofAttestation(_) => {
            inc_counter(&GOSSIP_AGGREGATED_ATTESTATIONS_RX)
        }
        _ => {}
    }
}

pub fn update_gossip_metrics<T: EthSpec>(
    gossipsub: &Gossipsub,
    network_globals: &Arc<NetworkGlobals<T>>,
) {
    // Clear the metrics
    let _ = PEERS_PER_PROTOCOL.as_ref().map(|gauge| gauge.reset());
    let _ = PEERS_PER_PROTOCOL.as_ref().map(|gauge| gauge.reset());
    let _ = MESH_PEERS_PER_MAIN_TOPIC
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = AVG_GOSSIPSUB_PEER_SCORE_PER_SUBNET_TOPIC
        .as_ref()
        .map(|gauge| gauge.reset());

    let _ = SCORES_BELOW_ZERO_PER_CLIENT
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = SCORES_BELOW_GOSSIP_THRESHOLD_PER_CLIENT
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = SCORES_BELOW_PUBLISH_THRESHOLD_PER_CLIENT
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = SCORES_BELOW_GREYLIST_THRESHOLD_PER_CLIENT
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = MIN_SCORES_PER_CLIENT.as_ref().map(|gauge| gauge.reset());
    let _ = MEDIAN_SCORES_PER_CLIENT.as_ref().map(|gauge| gauge.reset());
    let _ = MEAN_SCORES_PER_CLIENT.as_ref().map(|gauge| gauge.reset());
    let _ = MAX_SCORES_PER_CLIENT.as_ref().map(|gauge| gauge.reset());

    let _ = BEACON_BLOCK_MESH_PEERS_PER_CLIENT
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT
        .as_ref()
        .map(|gauge| gauge.reset());

    // reset the mesh peers, showing all subnets
    for subnet_id in 0..T::default_spec().attestation_subnet_count {
        let _ = get_int_gauge(
            &MESH_PEERS_PER_SUBNET_TOPIC,
            &[subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));

        let _ = get_int_gauge(
            &GOSSIPSUB_SUBSCRIBED_SUBNET_TOPIC,
            &[subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));

        let _ = get_int_gauge(
            &GOSSIPSUB_SUBSCRIBED_PEERS_SUBNET_TOPIC,
            &[subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));
    }

    // Subnet topics subscribed to
    for topic_hash in gossipsub.topics() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            if let GossipKind::Attestation(subnet_id) = topic.kind() {
                let _ = get_int_gauge(
                    &GOSSIPSUB_SUBSCRIBED_SUBNET_TOPIC,
                    &[subnet_id_to_string(subnet_id.into())],
                )
                .map(|v| v.set(1));
            }
        }
    }

    // Peers per subscribed subnet
    let mut peers_per_topic: HashMap<TopicHash, usize> = HashMap::new();
    for (peer_id, topics) in gossipsub.all_peers() {
        for topic_hash in topics {
            *peers_per_topic.entry(topic_hash.clone()).or_default() += 1;

            if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
                match topic.kind() {
                    GossipKind::Attestation(subnet_id) => {
                        if let Some(v) = get_int_gauge(
                            &GOSSIPSUB_SUBSCRIBED_PEERS_SUBNET_TOPIC,
                            &[subnet_id_to_string(subnet_id.into())],
                        ) {
                            v.inc()
                        };

                        // average peer scores
                        if let Some(score) = gossipsub.peer_score(peer_id) {
                            if let Some(v) = get_gauge(
                                &AVG_GOSSIPSUB_PEER_SCORE_PER_SUBNET_TOPIC,
                                &[subnet_id_to_string(subnet_id.into())],
                            ) {
                                v.add(score)
                            };
                        }
                    }
                    kind => {
                        // main topics
                        if let Some(score) = gossipsub.peer_score(peer_id) {
                            if let Some(v) = get_gauge(
                                &AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC,
                                &[kind.as_ref()],
                            ) {
                                v.add(score)
                            };
                        }
                    }
                }
            }
        }
    }
    // adjust to average scores by dividing by number of peers
    for (topic_hash, peers) in peers_per_topic.iter() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::Attestation(subnet_id) => {
                    // average peer scores
                    if let Some(v) = get_gauge(
                        &AVG_GOSSIPSUB_PEER_SCORE_PER_SUBNET_TOPIC,
                        &[subnet_id_to_string(subnet_id.into())],
                    ) {
                        v.set(v.get() / (*peers as f64))
                    };
                }
                kind => {
                    // main topics
                    if let Some(v) =
                        get_gauge(&AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC, &[kind.as_ref()])
                    {
                        v.set(v.get() / (*peers as f64))
                    };
                }
            }
        }
    }

    // mesh peers
    for topic_hash in gossipsub.topics() {
        let peers = gossipsub.mesh_peers(&topic_hash).count();
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::Attestation(subnet_id) => {
                    if let Some(v) = get_int_gauge(
                        &MESH_PEERS_PER_SUBNET_TOPIC,
                        &[subnet_id_to_string(subnet_id.into())],
                    ) {
                        v.set(peers as i64)
                    };
                }
                kind => {
                    // main topics
                    if let Some(v) = get_int_gauge(&MESH_PEERS_PER_MAIN_TOPIC, &[kind.as_ref()]) {
                        v.set(peers as i64)
                    };
                }
            }
        }
    }

    // protocol peers
    let mut peers_per_protocol: HashMap<&'static str, i64> = HashMap::new();
    for (_peer, protocol) in gossipsub.peer_protocol() {
        *peers_per_protocol
            .entry(protocol.as_static_ref())
            .or_default() += 1;
    }

    for (protocol, peers) in peers_per_protocol.iter() {
        if let Some(v) = get_int_gauge(&PEERS_PER_PROTOCOL, &[protocol]) {
            v.set(*peers)
        };
    }

    let mut peer_to_client = HashMap::new();
    let mut scores_per_client: HashMap<&'static str, Vec<f64>> = HashMap::new();
    {
        let peers = network_globals.peers.read();
        for (peer_id, _) in gossipsub.all_peers() {
            let client = peers
                .peer_info(peer_id)
                .map(|peer_info| peer_info.client.kind.as_static_ref())
                .unwrap_or_else(|| "Unknown");

            peer_to_client.insert(peer_id, client);
            let score = gossipsub.peer_score(peer_id).unwrap_or(0.0);
            scores_per_client.entry(client).or_default().push(score);
        }
    }

    // mesh peers per client
    for topic_hash in gossipsub.topics() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::BeaconBlock => {
                    for peer in gossipsub.mesh_peers(&topic_hash) {
                        if let Some(client) = peer_to_client.get(peer) {
                            if let Some(v) =
                                get_int_gauge(&BEACON_BLOCK_MESH_PEERS_PER_CLIENT, &[client])
                            {
                                v.inc()
                            };
                        }
                    }
                }
                GossipKind::BeaconAggregateAndProof => {
                    for peer in gossipsub.mesh_peers(&topic_hash) {
                        if let Some(client) = peer_to_client.get(peer) {
                            if let Some(v) = get_int_gauge(
                                &BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT,
                                &[client],
                            ) {
                                v.inc()
                            };
                        }
                    }
                }
                _ => (),
            }
        }
    }

    for (client, scores) in scores_per_client.into_iter() {
        let c = &[client];
        let len = scores.len();
        if len > 0 {
            let mut below0 = 0;
            let mut below_gossip_threshold = 0;
            let mut below_publish_threshold = 0;
            let mut below_greylist_threshold = 0;
            let mut min = f64::INFINITY;
            let mut sum = 0.0;
            let mut max = f64::NEG_INFINITY;

            let count = scores.len() as f64;

            for &score in &scores {
                if score < 0.0 {
                    below0 += 1;
                }
                if score < -4000.0 {
                    //TODO not hardcode
                    below_gossip_threshold += 1;
                }
                if score < -8000.0 {
                    //TODO not hardcode
                    below_publish_threshold += 1;
                }
                if score < -16000.0 {
                    //TODO not hardcode
                    below_greylist_threshold += 1;
                }
                if score < min {
                    min = score;
                }
                if score > max {
                    max = score;
                }
                sum += score;
            }

            let median = if len == 0 {
                0.0
            } else if len % 2 == 0 {
                (scores[len / 2 - 1] + scores[len / 2]) / 2.0
            } else {
                scores[len / 2]
            };

            set_gauge_entry(&SCORES_BELOW_ZERO_PER_CLIENT, c, below0 as f64 / count);
            set_gauge_entry(
                &SCORES_BELOW_GOSSIP_THRESHOLD_PER_CLIENT,
                c,
                below_gossip_threshold as f64 / count,
            );
            set_gauge_entry(
                &SCORES_BELOW_PUBLISH_THRESHOLD_PER_CLIENT,
                c,
                below_publish_threshold as f64 / count,
            );
            set_gauge_entry(
                &SCORES_BELOW_GREYLIST_THRESHOLD_PER_CLIENT,
                c,
                below_greylist_threshold as f64 / count,
            );

            set_gauge_entry(&MIN_SCORES_PER_CLIENT, c, min);
            set_gauge_entry(&MEDIAN_SCORES_PER_CLIENT, c, median);
            set_gauge_entry(&MEAN_SCORES_PER_CLIENT, c, sum / count);
            set_gauge_entry(&MAX_SCORES_PER_CLIENT, c, max);
        }
    }
}

pub fn update_sync_metrics<T: EthSpec>(network_globals: &Arc<NetworkGlobals<T>>) {
    // reset the counts
    if PEERS_PER_SYNC_TYPE
        .as_ref()
        .map(|metric| metric.reset())
        .is_err()
    {
        return;
    };

    // count per sync status, the number of connected peers
    let mut peers_per_sync_type = FnvHashMap::default();
    for sync_type in network_globals
        .peers
        .read()
        .connected_peers()
        .map(|(_peer_id, info)| info.sync_status.as_str())
    {
        *peers_per_sync_type.entry(sync_type).or_default() += 1;
    }

    for (sync_type, peer_count) in peers_per_sync_type {
        set_gauge_entry(&PEERS_PER_SYNC_TYPE, &[sync_type], peer_count);
    }
}
