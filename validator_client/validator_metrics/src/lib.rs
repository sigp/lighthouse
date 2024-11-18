use std::sync::LazyLock;

pub const SUCCESS: &str = "success";
pub const SLASHABLE: &str = "slashable";
pub const SAME_DATA: &str = "same_data";
pub const UNREGISTERED: &str = "unregistered";
pub const FULL_UPDATE: &str = "full_update";
pub const BEACON_BLOCK: &str = "beacon_block";
pub const BEACON_BLOCK_HTTP_GET: &str = "beacon_block_http_get";
pub const BEACON_BLOCK_HTTP_POST: &str = "beacon_block_http_post";
pub const BLINDED_BEACON_BLOCK_HTTP_POST: &str = "blinded_beacon_block_http_post";
pub const ATTESTATIONS: &str = "attestations";
pub const ATTESTATIONS_HTTP_GET: &str = "attestations_http_get";
pub const ATTESTATIONS_HTTP_POST: &str = "attestations_http_post";
pub const AGGREGATES: &str = "aggregates";
pub const AGGREGATES_HTTP_GET: &str = "aggregates_http_get";
pub const AGGREGATES_HTTP_POST: &str = "aggregates_http_post";
pub const CURRENT_EPOCH: &str = "current_epoch";
pub const NEXT_EPOCH: &str = "next_epoch";
pub const UPDATE_INDICES: &str = "update_indices";
pub const UPDATE_ATTESTERS_CURRENT_EPOCH: &str = "update_attesters_current_epoch";
pub const UPDATE_ATTESTERS_NEXT_EPOCH: &str = "update_attesters_next_epoch";
pub const UPDATE_ATTESTERS_FETCH: &str = "update_attesters_fetch";
pub const UPDATE_ATTESTERS_STORE: &str = "update_attesters_store";
pub const ATTESTER_DUTIES_HTTP_POST: &str = "attester_duties_http_post";
pub const PROPOSER_DUTIES_HTTP_GET: &str = "proposer_duties_http_get";
pub const VALIDATOR_DUTIES_SYNC_HTTP_POST: &str = "validator_duties_sync_http_post";
pub const VALIDATOR_ID_HTTP_GET: &str = "validator_id_http_get";
pub const SUBSCRIPTIONS_HTTP_POST: &str = "subscriptions_http_post";
pub const UPDATE_PROPOSERS: &str = "update_proposers";
pub const ATTESTATION_SELECTION_PROOFS: &str = "attestation_selection_proofs";
pub const SUBSCRIPTIONS: &str = "subscriptions";
pub const LOCAL_KEYSTORE: &str = "local_keystore";
pub const WEB3SIGNER: &str = "web3signer";

pub use metrics::*;

pub static GENESIS_DISTANCE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "vc_genesis_distance_seconds",
        "Distance between now and genesis time",
    )
});
pub static ENABLED_VALIDATORS_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "vc_validators_enabled_count",
        "Number of enabled validators",
    )
});
pub static TOTAL_VALIDATORS_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "vc_validators_total_count",
        "Number of total validators (enabled and disabled)",
    )
});

pub static SIGNED_BLOCKS_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "vc_signed_beacon_blocks_total",
        "Total count of attempted block signings",
        &["status"],
    )
});
pub static SIGNED_ATTESTATIONS_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "vc_signed_attestations_total",
        "Total count of attempted Attestation signings",
        &["status"],
    )
});
pub static SIGNED_AGGREGATES_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "vc_signed_aggregates_total",
        "Total count of attempted SignedAggregateAndProof signings",
        &["status"],
    )
});
pub static SIGNED_SELECTION_PROOFS_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "vc_signed_selection_proofs_total",
        "Total count of attempted SelectionProof signings",
        &["status"],
    )
});
pub static SIGNED_SYNC_COMMITTEE_MESSAGES_TOTAL: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "vc_signed_sync_committee_messages_total",
            "Total count of attempted SyncCommitteeMessage signings",
            &["status"],
        )
    });
pub static SIGNED_SYNC_COMMITTEE_CONTRIBUTIONS_TOTAL: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "vc_signed_sync_committee_contributions_total",
            "Total count of attempted ContributionAndProof signings",
            &["status"],
        )
    });
pub static SIGNED_SYNC_SELECTION_PROOFS_TOTAL: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "vc_signed_sync_selection_proofs_total",
            "Total count of attempted SyncSelectionProof signings",
            &["status"],
        )
    });
pub static SIGNED_VOLUNTARY_EXITS_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "vc_signed_voluntary_exits_total",
        "Total count of VoluntaryExit signings",
        &["status"],
    )
});
pub static SIGNED_VALIDATOR_REGISTRATIONS_TOTAL: LazyLock<Result<IntCounterVec>> =
    LazyLock::new(|| {
        try_create_int_counter_vec(
            "builder_validator_registrations_total",
            "Total count of ValidatorRegistrationData signings",
            &["status"],
        )
    });
pub static DUTIES_SERVICE_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "vc_duties_service_task_times_seconds",
        "Duration to perform duties service tasks",
        &["task"],
    )
});
pub static ATTESTATION_SERVICE_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "vc_attestation_service_task_times_seconds",
        "Duration to perform attestation service tasks",
        &["task"],
    )
});
pub static SLASHING_PROTECTION_PRUNE_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "vc_slashing_protection_prune_times_seconds",
        "Time required to prune the slashing protection DB",
    )
});
pub static BLOCK_SERVICE_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "vc_beacon_block_service_task_times_seconds",
        "Duration to perform beacon block service tasks",
        &["task"],
    )
});
pub static PROPOSER_COUNT: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "vc_beacon_block_proposer_count",
        "Number of beacon block proposers on this host",
        &["task"],
    )
});
pub static ATTESTER_COUNT: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "vc_beacon_attester_count",
        "Number of attesters on this host",
        &["task"],
    )
});
pub static PROPOSAL_CHANGED: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "vc_beacon_block_proposal_changed",
        "A duties update discovered a new block proposer for the current slot",
    )
});
/*
 * Endpoint metrics
 */
pub static ENDPOINT_ERRORS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "bn_endpoint_errors",
        "The number of beacon node request errors for each endpoint",
        &["endpoint"],
    )
});
pub static ENDPOINT_REQUESTS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "bn_endpoint_requests",
        "The number of beacon node requests for each endpoint",
        &["endpoint"],
    )
});

/*
 * Beacon node availability metrics
 */
pub static AVAILABLE_BEACON_NODES_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "vc_beacon_nodes_available_count",
        "Number of available beacon nodes",
    )
});
pub static SYNCED_BEACON_NODES_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "vc_beacon_nodes_synced_count",
        "Number of synced beacon nodes",
    )
});
pub static TOTAL_BEACON_NODES_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "vc_beacon_nodes_total_count",
        "Total number of beacon nodes",
    )
});

pub static ETH2_FALLBACK_CONFIGURED: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "sync_eth2_fallback_configured",
        "The number of configured eth2 fallbacks",
    )
});

pub static ETH2_FALLBACK_CONNECTED: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "sync_eth2_fallback_connected",
        "Set to 1 if connected to atleast one synced eth2 fallback node, otherwise set to 0",
    )
});
/*
 * Signing Metrics
 */
pub static SIGNING_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "vc_signing_times_seconds",
        "Duration to obtain a signature",
        &["type"],
    )
});
pub static BLOCK_SIGNING_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "vc_block_signing_times_seconds",
        "Duration to obtain a signature for a block",
    )
});

pub static ATTESTATION_DUTY: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "vc_attestation_duty_slot",
        "Attestation duty slot for all managed validators",
        &["validator"],
    )
});
/*
 * BN latency
 */
pub static VC_BEACON_NODE_LATENCY: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec(
        "vc_beacon_node_latency",
        "Round-trip latency for a simple API endpoint on each BN",
        &["endpoint"],
    )
});
pub static VC_BEACON_NODE_LATENCY_PRIMARY_ENDPOINT: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "vc_beacon_node_latency_primary_endpoint",
            "Round-trip latency for the primary BN endpoint",
        )
    });
