use beacon_chain::{
    attestation_verification::Error as AttnError,
    sync_committee_verification::Error as SyncCommitteeError,
};
use eth2_libp2p::PubsubMessage;
use eth2_libp2p::{
    types::GossipKind, BandwidthSinks, GossipTopic, Gossipsub, NetworkGlobals, TopicHash,
};
use fnv::FnvHashMap;
pub use lighthouse_metrics::*;
use std::{collections::HashMap, sync::Arc};
use strum::AsStaticRef;
use types::{
    consts::altair::SYNC_COMMITTEE_SUBNET_COUNT, subnet_id::subnet_id_to_string,
    sync_subnet_id::sync_subnet_id_to_string, EthSpec,
};

lazy_static! {

    /*
     * Gossip subnets and scoring
     */
    pub static ref PEERS_PER_PROTOCOL: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_peers_per_protocol",
        "Peers via supported protocol",
        &["protocol"]
    );

    pub static ref GOSSIPSUB_SUBSCRIBED_ATTESTATION_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_subscribed_attestation_subnets",
        "Attestation subnets currently subscribed to",
        &["subnet"]
    );

    pub static ref GOSSIPSUB_SUBSCRIBED_SYNC_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_subscribed_sync_subnets",
        "Sync subnets currently subscribed to",
        &["subnet"]
    );

    pub static ref GOSSIPSUB_SUBSCRIBED_PEERS_ATTESTATION_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_peers_per_attestation_subnet_topic_count",
        "Peers subscribed per attestation subnet topic",
        &["subnet"]
    );

    pub static ref GOSSIPSUB_SUBSCRIBED_PEERS_SYNC_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_peers_per_sync_subnet_topic_count",
        "Peers subscribed per sync subnet topic",
        &["subnet"]
    );

    pub static ref MESH_PEERS_PER_MAIN_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_mesh_peers_per_main_topic",
        "Mesh peers per main topic",
        &["topic_hash"]
    );

    pub static ref MESH_PEERS_PER_ATTESTATION_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_mesh_peers_per_subnet_topic",
        "Mesh peers per subnet topic",
        &["subnet"]
    );

    pub static ref MESH_PEERS_PER_SYNC_SUBNET_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_mesh_peers_per_subnet_topic",
        "Mesh peers per subnet topic",
        &["subnet"]
    );

    pub static ref AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_avg_peer_score_per_topic",
        "Average peer's score per topic",
        &["topic_hash"]
    );

    pub static ref AVG_GOSSIPSUB_PEER_SCORE_PER_ATTESTATION_SUBNET_TOPIC: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_avg_peer_score_per_attestation_subnet_topic",
        "Average peer's score per attestation subnet topic",
        &["subnet"]
    );

    pub static ref AVG_GOSSIPSUB_PEER_SCORE_PER_SYNC_SUBNET_TOPIC: Result<GaugeVec> = try_create_float_gauge_vec(
        "gossipsub_avg_peer_score_per_sync_subnet_topic",
        "Average peer's score per sync committee subnet topic",
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
    pub static ref GOSSIP_SYNC_COMMITTEE_MESSAGE_RX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_sync_committee_message_rx_total",
        "Count of gossip sync committee messages received"
    );
    pub static ref GOSSIP_SYNC_COMMITTEE_CONTRIBUTION_RX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_sync_committee_contribution_received_total",
        "Count of gossip sync committee contributions received"
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
    pub static ref GOSSIP_SYNC_COMMITTEE_MESSAGE_TX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_sync_committee_message_tx_total",
        "Count of gossip sync committee messages transmitted"
    );
    pub static ref GOSSIP_SYNC_COMMITTEE_CONTRIBUTION_TX: Result<IntCounter> = try_create_int_counter(
        "gossipsub_sync_committee_contribution_tx_total",
        "Count of gossip sync committee contributions transmitted"
    );

    /*
     * Attestation subnet subscriptions
     */
    pub static ref SUBNET_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "gossipsub_attestation_subnet_subscriptions_total",
        "Count of validator attestation subscription requests."
    );
    pub static ref SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "gossipsub_subnet_subscriptions_aggregator_total",
        "Count of validator subscription requests where the subscriber is an aggregator."
    );

    /*
     * Sync committee subnet subscriptions
     */
     pub static ref SYNC_COMMITTEE_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "gossipsub_sync_committee_subnet_subscriptions_total",
        "Count of validator sync committee subscription requests."
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

}

lazy_static! {
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

    /*
     * Block Delay Metrics
     */
    pub static ref BEACON_BLOCK_GOSSIP_PROPAGATION_VERIFICATION_DELAY_TIME: Result<Histogram> = try_create_histogram(
        "beacon_block_gossip_propagation_verification_delay_time",
        "Duration between when the block is received and when it is verified for propagation.",
    );
    pub static ref BEACON_BLOCK_GOSSIP_SLOT_START_DELAY_TIME: Result<Histogram> = try_create_histogram(
        "beacon_block_gossip_slot_start_delay_time",
        "Duration between when the block is received and the start of the slot it belongs to.",
    );
    pub static ref BEACON_BLOCK_GOSSIP_ARRIVED_LATE_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_block_gossip_arrived_late_total",
        "Count of times when a gossip block arrived from the network later than the attestation deadline.",
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
        "Number of queued attestations which have expired before a matching block has been found"
    );
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_MATCHED_ATTESTATIONS: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_reprocessing_queue_matched_attestations",
        "Number of queued attestations where as matching block has been imported"
    );
}

pub fn register_attestation_error(error: &AttnError) {
    inc_counter_vec(&GOSSIP_ATTESTATION_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn register_sync_committee_error(error: &SyncCommitteeError) {
    inc_counter_vec(&GOSSIP_SYNC_COMMITTEE_ERRORS_PER_TYPE, &[error.as_ref()]);
}

/// Inspects the `messages` that were being sent to the network and updates Prometheus metrics.
pub fn expose_publish_metrics<T: EthSpec>(messages: &[PubsubMessage<T>]) {
    for message in messages {
        match message {
            PubsubMessage::BeaconBlock(_) => inc_counter(&GOSSIP_BLOCKS_TX),
            PubsubMessage::Attestation(subnet_id) => {
                inc_counter_vec(
                    &ATTESTATIONS_PUBLISHED_PER_SUBNET_PER_SLOT,
                    &[subnet_id.0.as_ref()],
                );
                inc_counter(&GOSSIP_UNAGGREGATED_ATTESTATIONS_TX)
            }
            PubsubMessage::AggregateAndProofAttestation(_) => {
                inc_counter(&GOSSIP_AGGREGATED_ATTESTATIONS_TX)
            }
            PubsubMessage::SyncCommitteeMessage(_) => {
                inc_counter(&GOSSIP_SYNC_COMMITTEE_MESSAGE_TX)
            }
            PubsubMessage::SignedContributionAndProof(_) => {
                inc_counter(&GOSSIP_SYNC_COMMITTEE_CONTRIBUTION_TX)
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
        PubsubMessage::SyncCommitteeMessage(_) => inc_counter(&GOSSIP_SYNC_COMMITTEE_MESSAGE_RX),
        PubsubMessage::SignedContributionAndProof(_) => {
            inc_counter(&GOSSIP_SYNC_COMMITTEE_CONTRIBUTION_RX)
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
    let _ = AVG_GOSSIPSUB_PEER_SCORE_PER_ATTESTATION_SUBNET_TOPIC
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = AVG_GOSSIPSUB_PEER_SCORE_PER_SYNC_SUBNET_TOPIC
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
            &MESH_PEERS_PER_ATTESTATION_SUBNET_TOPIC,
            &[subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));

        let _ = get_int_gauge(
            &GOSSIPSUB_SUBSCRIBED_ATTESTATION_SUBNET_TOPIC,
            &[subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));

        let _ = get_int_gauge(
            &GOSSIPSUB_SUBSCRIBED_PEERS_ATTESTATION_SUBNET_TOPIC,
            &[subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));
    }

    for subnet_id in 0..SYNC_COMMITTEE_SUBNET_COUNT {
        let _ = get_int_gauge(
            &MESH_PEERS_PER_SYNC_SUBNET_TOPIC,
            &[sync_subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));

        let _ = get_int_gauge(
            &GOSSIPSUB_SUBSCRIBED_SYNC_SUBNET_TOPIC,
            &[sync_subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));

        let _ = get_int_gauge(
            &GOSSIPSUB_SUBSCRIBED_PEERS_SYNC_SUBNET_TOPIC,
            &[sync_subnet_id_to_string(subnet_id)],
        )
        .map(|v| v.set(0));
    }

    // Subnet topics subscribed to
    for topic_hash in gossipsub.topics() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            if let GossipKind::Attestation(subnet_id) = topic.kind() {
                let _ = get_int_gauge(
                    &GOSSIPSUB_SUBSCRIBED_ATTESTATION_SUBNET_TOPIC,
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
                            &GOSSIPSUB_SUBSCRIBED_PEERS_ATTESTATION_SUBNET_TOPIC,
                            &[subnet_id_to_string(subnet_id.into())],
                        ) {
                            v.inc()
                        };

                        // average peer scores
                        if let Some(score) = gossipsub.peer_score(peer_id) {
                            if let Some(v) = get_gauge(
                                &AVG_GOSSIPSUB_PEER_SCORE_PER_ATTESTATION_SUBNET_TOPIC,
                                &[subnet_id_to_string(subnet_id.into())],
                            ) {
                                v.add(score)
                            };
                        }
                    }
                    GossipKind::SyncCommitteeMessage(subnet_id) => {
                        if let Some(v) = get_int_gauge(
                            &GOSSIPSUB_SUBSCRIBED_PEERS_SYNC_SUBNET_TOPIC,
                            &[sync_subnet_id_to_string(subnet_id.into())],
                        ) {
                            v.inc()
                        };

                        // average peer scores
                        if let Some(score) = gossipsub.peer_score(peer_id) {
                            if let Some(v) = get_gauge(
                                &AVG_GOSSIPSUB_PEER_SCORE_PER_SYNC_SUBNET_TOPIC,
                                &[sync_subnet_id_to_string(subnet_id.into())],
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
                        &AVG_GOSSIPSUB_PEER_SCORE_PER_ATTESTATION_SUBNET_TOPIC,
                        &[subnet_id_to_string(subnet_id.into())],
                    ) {
                        v.set(v.get() / (*peers as f64))
                    };
                }
                GossipKind::SyncCommitteeMessage(subnet_id) => {
                    // average peer scores
                    if let Some(v) = get_gauge(
                        &AVG_GOSSIPSUB_PEER_SCORE_PER_SYNC_SUBNET_TOPIC,
                        &[sync_subnet_id_to_string(subnet_id.into())],
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
        let peers = gossipsub.mesh_peers(topic_hash).count();
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::Attestation(subnet_id) => {
                    if let Some(v) = get_int_gauge(
                        &MESH_PEERS_PER_ATTESTATION_SUBNET_TOPIC,
                        &[subnet_id_to_string(subnet_id.into())],
                    ) {
                        v.set(peers as i64)
                    };
                }
                GossipKind::SyncCommitteeMessage(subnet_id) => {
                    if let Some(v) = get_int_gauge(
                        &MESH_PEERS_PER_SYNC_SUBNET_TOPIC,
                        &[sync_subnet_id_to_string(subnet_id.into())],
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
                .map(|peer_info| peer_info.client().kind.as_static())
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
                    for peer in gossipsub.mesh_peers(topic_hash) {
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
                    for peer in gossipsub.mesh_peers(topic_hash) {
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
        .map(|(_peer_id, info)| info.sync_status().as_str())
    {
        *peers_per_sync_type.entry(sync_type).or_default() += 1;
    }

    for (sync_type, peer_count) in peers_per_sync_type {
        set_gauge_entry(&PEERS_PER_SYNC_TYPE, &[sync_type], peer_count);
    }
}
