use beacon_chain::{
    attestation_verification::Error as AttnError,
    light_client_finality_update_verification::Error as LightClientFinalityUpdateError,
    light_client_optimistic_update_verification::Error as LightClientOptimisticUpdateError,
    sync_committee_verification::Error as SyncCommitteeError,
};
use fnv::FnvHashMap;
pub use lighthouse_metrics::*;
use lighthouse_network::{
    peer_manager::peerdb::client::ClientKind, types::GossipKind, GossipTopic, Gossipsub,
    NetworkGlobals,
};
use std::sync::Arc;
use strum::IntoEnumIterator;
use types::EthSpec;

pub const SUCCESS: &str = "SUCCESS";
pub const FAILURE: &str = "FAILURE";

lazy_static! {

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

    /*
     * Attestation subnet subscriptions
     */
    pub static ref SUBNET_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "validator_attestation_subnet_subscriptions_total",
        "Count of validator attestation subscription requests."
    );
    pub static ref SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "validator_subnet_subscriptions_aggregator_total",
        "Count of validator subscription requests where the subscriber is an aggregator."
    );
    pub static ref SYNC_COMMITTEE_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "validator_sync_committee_subnet_subscriptions_total",
        "Count of validator sync committee subscription requests."
    );

    /*
     * Gossip processor
     */

    // Gossip blocks.
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
    pub static ref BEACON_PROCESSOR_GOSSIP_BLOB_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_gossip_blob_verified_total",
        "Total number of gossip blob verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_GOSSIP_DATA_COLUMN_SIDECAR_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_gossip_data_column_verified_total",
        "Total number of gossip data column sidecar verified for propagation."
    );
    // Gossip Exits.
    pub static ref BEACON_PROCESSOR_EXIT_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_exit_verified_total",
        "Total number of voluntary exits verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_EXIT_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_exit_imported_total",
        "Total number of voluntary exits imported to the op pool."
    );
    // Gossip proposer slashings.
    pub static ref BEACON_PROCESSOR_PROPOSER_SLASHING_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_proposer_slashing_verified_total",
        "Total number of proposer slashings verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_PROPOSER_SLASHING_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_proposer_slashing_imported_total",
        "Total number of proposer slashings imported to the op pool."
    );
    // Gossip attester slashings.
    pub static ref BEACON_PROCESSOR_ATTESTER_SLASHING_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_attester_slashing_verified_total",
        "Total number of attester slashings verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_ATTESTER_SLASHING_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_attester_slashing_imported_total",
        "Total number of attester slashings imported to the op pool."
    );
    // Gossip BLS to execution changes.
    pub static ref BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_bls_to_execution_change_verified_total",
        "Total number of address changes verified for propagation."
    );
    pub static ref BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_bls_to_execution_change_imported_total",
        "Total number of address changes imported to the op pool."
    );
}

// Need to split up this `lazy_static!` due to recursion limits.
lazy_static! {
    // Rpc blocks.
    pub static ref BEACON_PROCESSOR_RPC_BLOCK_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_rpc_block_imported_total",
        "Total number of gossip blocks imported to fork choice, etc."
    );
    // Chain segments.
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
    pub static ref BEACON_PROCESSOR_SYNC_MESSAGE_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_message_verified_total",
        "Total number of sync committee messages verified for gossip."
    );
    pub static ref BEACON_PROCESSOR_SYNC_MESSAGE_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_message_imported_total",
        "Total number of sync committee messages imported to fork choice, etc."
    );
    // Sync contribution.
    pub static ref BEACON_PROCESSOR_SYNC_CONTRIBUTION_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_contribution_verified_total",
        "Total number of sync committee contributions verified for gossip."
    );

    pub static ref BEACON_PROCESSOR_SYNC_CONTRIBUTION_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_sync_contribution_imported_total",
        "Total number of sync committee contributions imported to fork choice, etc."
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


    /*
     * Network queue metrics
     */
    pub static ref NETWORK_RECEIVE_EVENTS: Result<IntCounterVec> = try_create_int_counter_vec(
        "network_receive_events",
        "Count of events received by the channel to the network service",
        &["type"]
    );
    pub static ref NETWORK_RECEIVE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "network_receive_times",
        "Time taken for network to handle an event sent to the network service.",
        &["type"]
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
    pub static ref SYNC_SINGLE_BLOCK_LOOKUPS: Result<IntGauge> = try_create_int_gauge(
        "sync_single_block_lookups",
        "Number of single block lookups underway"
    );
    pub static ref SYNC_PARENT_BLOCK_LOOKUPS: Result<IntGauge> = try_create_int_gauge(
        "sync_parent_block_lookups",
        "Number of parent block lookups underway"
    );

    /*
     * Block Delay Metrics
     */
    pub static ref BEACON_BLOCK_DELAY_GOSSIP: Result<IntGauge> = try_create_int_gauge(
        "beacon_block_delay_gossip",
        "The first time we see this block from gossip as a delay from the start of the slot"
    );
    pub static ref BEACON_BLOCK_DELAY_GOSSIP_VERIFICATION: Result<IntGauge> = try_create_int_gauge(
        "beacon_block_delay_gossip_verification",
        "Keeps track of the time delay from the start of the slot to the point we propagate the block"
    );
    pub static ref BEACON_BLOCK_DELAY_FULL_VERIFICATION: Result<IntGauge> = try_create_int_gauge(
        "beacon_block_delay_full_verification",
        "The time it takes to verify a beacon block."
    );

    pub static ref BEACON_BLOCK_DELAY_GOSSIP_ARRIVED_LATE_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_block_delay_gossip_arrived_late_total",
        "Count of times when a gossip block arrived from the network later than the attestation deadline.",
    );

    /*
     * Blob Delay Metrics
     */
    pub static ref BEACON_BLOB_DELAY_GOSSIP: Result<IntGauge> = try_create_int_gauge(
        "beacon_blob_delay_gossip_last_delay",
        "The first time we see this blob as a delay from the start of the slot"
    );

    pub static ref BEACON_DATA_COLUMN_GOSSIP_PROPAGATION_VERIFICATION_DELAY_TIME: Result<Histogram> = try_create_histogram_with_buckets(
        "beacon_data_column_gossip_propagation_verification_delay_time",
        "Duration between when the data column sidecar is received over gossip and when it is verified for propagation.",
        // [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5]
        decimal_buckets(-3,-1)
    );
    pub static ref BEACON_BLOB_GOSSIP_SLOT_START_DELAY_TIME: Result<Histogram> = try_create_histogram_with_buckets(
        "beacon_blob_gossip_slot_start_delay_time",
        "Duration between when the blob is received over gossip and the start of the slot it belongs to.",
        // Create a custom bucket list for greater granularity in block delay
        Ok(vec![0.1, 0.2, 0.3,0.4,0.5,0.75,1.0,1.25,1.5,1.75,2.0,2.5,3.0,3.5,4.0,5.0,6.0,7.0,8.0,9.0,10.0,15.0,20.0])
        // NOTE: Previous values, which we may want to switch back to.
        // [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50]
        //decimal_buckets(-1,2)
    );
    pub static ref BEACON_DATA_COLUMN_GOSSIP_SLOT_START_DELAY_TIME: Result<Histogram> = try_create_histogram_with_buckets(
        "beacon_data_column_gossip_slot_start_delay_time",
        "Duration between when the data column sidecar is received over gossip and the start of the slot it belongs to.",
        // Create a custom bucket list for greater granularity in block delay
        Ok(vec![0.1, 0.2, 0.3,0.4,0.5,0.75,1.0,1.25,1.5,1.75,2.0,2.5,3.0,3.5,4.0,5.0,6.0,7.0,8.0,9.0,10.0,15.0,20.0])
        // NOTE: Previous values, which we may want to switch back to.
        // [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50]
        //decimal_buckets(-1,2)
    );

    pub static ref BEACON_BLOB_DELAY_GOSSIP_VERIFICATION: Result<IntGauge> = try_create_int_gauge(
        "beacon_blob_delay_gossip_verification",
        "Keeps track of the time delay from the start of the slot to the point we propagate the blob"
    );
    pub static ref BEACON_BLOB_DELAY_FULL_VERIFICATION: Result<IntGauge> = try_create_int_gauge(
        "beacon_blob_last_full_verification_delay",
        "The time it takes to verify a beacon blob"
    );

    pub static ref BEACON_BLOB_RPC_SLOT_START_DELAY_TIME: Result<Histogram> = try_create_histogram_with_buckets(
        "beacon_blob_rpc_slot_start_delay_time",
        "Duration between when a blob is received over rpc and the start of the slot it belongs to.",
        // Create a custom bucket list for greater granularity in block delay
        Ok(vec![0.1, 0.2, 0.3,0.4,0.5,0.75,1.0,1.25,1.5,1.75,2.0,2.5,3.0,3.5,4.0,5.0,6.0,7.0,8.0,9.0,10.0,15.0,20.0])
        // NOTE: Previous values, which we may want to switch back to.
        // [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50]
        //decimal_buckets(-1,2)

    );

    pub static ref BEACON_BLOB_LAST_DELAY: Result<IntGauge> = try_create_int_gauge(
        "beacon_blob_last_delay",
        "Keeps track of the last blob's delay from the start of the slot"
    );
    pub static ref BEACON_DATA_COLUMN_LAST_DELAY: Result<IntGauge> = try_create_int_gauge(
        "beacon_data_column_last_delay",
        "Keeps track of the last data column sidecar's delay from the start of the slot"
    );

    pub static ref BEACON_BLOB_GOSSIP_ARRIVED_LATE_TOTAL: Result<IntCounter> = try_create_int_counter(
        "beacon_blob_gossip_arrived_late_total",
        "Count of times when a gossip blob arrived from the network later than the attestation deadline.",
    );

    /*
     * Light client update reprocessing queue metrics.
     */
    pub static ref BEACON_PROCESSOR_REPROCESSING_QUEUE_SENT_OPTIMISTIC_UPDATES: Result<IntCounter> = try_create_int_counter(
        "beacon_processor_reprocessing_queue_sent_optimistic_updates",
        "Number of queued light client optimistic updates where as matching block has been imported."
    );

    /*
     * Sampling
     */
    pub static ref SAMPLE_DOWNLOAD_RESULT: Result<IntCounterVec> = try_create_int_counter_vec(
        "beacon_sampling_sample_verify_result_total",
        "Total count of individual sample download results",
        &["result"]
    );
    pub static ref SAMPLE_VERIFY_RESULT: Result<IntCounterVec> = try_create_int_counter_vec(
        "beacon_sampling_sample_verify_result_total",
        "Total count of individual sample verify results",
        &["result"]
    );
    pub static ref SAMPLING_REQUEST_RESULT: Result<IntCounterVec> = try_create_int_counter_vec(
        "beacon_sampling_request_result_total",
        "Total count of sample request results",
        &["result"]
    );
}

pub fn register_finality_update_error(error: &LightClientFinalityUpdateError) {
    inc_counter_vec(&GOSSIP_FINALITY_UPDATE_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn register_optimistic_update_error(error: &LightClientOptimisticUpdateError) {
    inc_counter_vec(&GOSSIP_OPTIMISTIC_UPDATE_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn register_attestation_error(error: &AttnError) {
    inc_counter_vec(&GOSSIP_ATTESTATION_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn register_sync_committee_error(error: &SyncCommitteeError) {
    inc_counter_vec(&GOSSIP_SYNC_COMMITTEE_ERRORS_PER_TYPE, &[error.as_ref()]);
}

pub fn from_result<T, E>(result: &std::result::Result<T, E>) -> &str {
    match result {
        Ok(_) => SUCCESS,
        Err(_) => FAILURE,
    }
}

pub fn update_gossip_metrics<E: EthSpec>(
    gossipsub: &Gossipsub,
    network_globals: &Arc<NetworkGlobals<E>>,
) {
    // Mesh peers per client
    // Reset the gauges
    for client_kind in ClientKind::iter() {
        set_gauge_vec(
            &BEACON_BLOCK_MESH_PEERS_PER_CLIENT,
            &[client_kind.as_ref()],
            0_i64,
        );
        set_gauge_vec(
            &BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT,
            &[client_kind.as_ref()],
            0_i64,
        );
    }

    for topic_hash in gossipsub.topics() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::Attestation(_subnet_id) => {}
                GossipKind::BeaconBlock => {
                    for peer_id in gossipsub.mesh_peers(topic_hash) {
                        let client = network_globals
                            .peers
                            .read()
                            .peer_info(peer_id)
                            .map(|peer_info| peer_info.client().kind.into())
                            .unwrap_or_else(|| "Unknown");
                        if let Some(v) =
                            get_int_gauge(&BEACON_BLOCK_MESH_PEERS_PER_CLIENT, &[client])
                        {
                            v.inc()
                        };
                    }
                }
                GossipKind::BeaconAggregateAndProof => {
                    for peer_id in gossipsub.mesh_peers(topic_hash) {
                        let client = network_globals
                            .peers
                            .read()
                            .peer_info(peer_id)
                            .map(|peer_info| peer_info.client().kind.into())
                            .unwrap_or_else(|| "Unknown");
                        if let Some(v) = get_int_gauge(
                            &BEACON_AGGREGATE_AND_PROOF_MESH_PEERS_PER_CLIENT,
                            &[client],
                        ) {
                            v.inc()
                        };
                    }
                }
                GossipKind::SyncCommitteeMessage(_subnet_id) => {}
                _kind => {}
            }
        }
    }
}

pub fn update_sync_metrics<E: EthSpec>(network_globals: &Arc<NetworkGlobals<E>>) {
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
