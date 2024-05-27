pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref NAT_OPEN: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "nat_open",
        "An estimate indicating if the local node is reachable from external nodes",
        &["protocol"]
    );
    pub static ref ADDRESS_UPDATE_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_address_update_total",
        "Count of libp2p socked updated events (when our view of our IP address has changed)"
    );
    pub static ref PEERS_CONNECTED: Result<IntGauge> = try_create_int_gauge(
        "libp2p_peers",
        "Count of libp2p peers currently connected"
    );

    pub static ref PEERS_CONNECTED_MULTI: Result<IntGaugeVec> =
    try_create_int_gauge_vec("libp2p_peers_multi", "Count of libp2p peers currently connected", &["direction", "transport"]);

    pub static ref TCP_PEERS_CONNECTED: Result<IntGauge> = try_create_int_gauge(
        "libp2p_tcp_peers",
        "Count of libp2p peers currently connected via TCP"
    );

    pub static ref QUIC_PEERS_CONNECTED: Result<IntGauge> = try_create_int_gauge(
        "libp2p_quic_peers",
        "Count of libp2p peers currently connected via QUIC"
    );

    pub static ref PEER_CONNECT_EVENT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_connect_event_total",
        "Count of libp2p peer connect events (not the current number of connected peers)"
    );
    pub static ref PEER_DISCONNECT_EVENT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_disconnect_event_total",
        "Count of libp2p peer disconnect events"
    );
    pub static ref DISCOVERY_BYTES: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "discovery_bytes",
        "The number of bytes sent and received in discovery",
        &["direction"]
    );
    pub static ref DISCOVERY_QUEUE: Result<IntGauge> = try_create_int_gauge(
        "discovery_queue_size",
        "The number of discovery queries awaiting execution"
    );
    pub static ref DISCOVERY_REQS: Result<Gauge> = try_create_float_gauge(
        "discovery_requests",
        "The number of unsolicited discovery requests per second"
    );
    pub static ref DISCOVERY_SESSIONS: Result<IntGauge> = try_create_int_gauge(
        "discovery_sessions",
        "The number of active discovery sessions with peers"
    );

    pub static ref PEERS_PER_CLIENT: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "libp2p_peers_per_client",
        "The connected peers via client implementation",
        &["Client"]
    );
    pub static ref FAILED_ATTESTATION_PUBLISHES_PER_SUBNET: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "gossipsub_failed_attestation_publishes_per_subnet",
            "Failed attestation publishes per subnet",
            &["subnet"]
        );
    pub static ref FAILED_PUBLISHES_PER_MAIN_TOPIC: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "gossipsub_failed_publishes_per_main_topic",
        "Failed gossip publishes",
        &["topic_hash"]
    );
    pub static ref TOTAL_RPC_ERRORS_PER_CLIENT: Result<IntCounterVec> = try_create_int_counter_vec(
        "libp2p_rpc_errors_per_client",
        "RPC errors per client",
        &["client", "rpc_error", "direction"]
    );
    pub static ref TOTAL_RPC_REQUESTS: Result<IntCounterVec> = try_create_int_counter_vec(
        "libp2p_rpc_requests_total",
        "RPC requests total",
        &["type"]
    );
    pub static ref PEER_ACTION_EVENTS_PER_CLIENT: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "libp2p_peer_actions_per_client",
            "Score reports per client",
            &["client", "action", "source"]
        );
    pub static ref GOSSIP_UNACCEPTED_MESSAGES_PER_CLIENT: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_unaccepted_messages_per_client",
            "Gossipsub messages that we did not accept, per client",
            &["client", "validation_result"]
        );
    pub static ref GOSSIP_LATE_PUBLISH_PER_TOPIC_KIND: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_late_publish_per_topic_kind",
            "Messages published late to gossipsub per topic kind.",
            &["topic_kind"]
        );
    pub static ref GOSSIP_EXPIRED_LATE_PUBLISH_PER_TOPIC_KIND: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_expired_late_publish_per_topic_kind",
            "Messages that expired waiting to be published on retry to gossipsub per topic kind.",
            &["topic_kind"]
        );
    pub static ref GOSSIP_FAILED_LATE_PUBLISH_PER_TOPIC_KIND: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "gossipsub_failed_late_publish_per_topic_kind",
            "Messages that failed to be published on retry to gossipsub per topic kind.",
            &["topic_kind"]
        );
    pub static ref PEER_SCORE_DISTRIBUTION: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "peer_score_distribution",
            "The distribution of connected peer scores",
            &["position"]
        );
    pub static ref PEER_SCORE_PER_CLIENT: Result<GaugeVec> =
        try_create_float_gauge_vec(
            "peer_score_per_client",
            "Average score per client",
            &["client"]
        );

    pub static ref SUBNET_PEERS_FOUND: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "discovery_query_peers_found",
            "Total number of peers found in attestation subnets and sync subnets",
            &["type"]
        );
    pub static ref TOTAL_SUBNET_QUERIES: Result<IntCounterVec> =
        try_create_int_counter_vec(
            "discovery_total_queries",
            "Total number of discovery subnet queries",
            &["type"]
        );

    /*
     * Peer Reporting
     */
    pub static ref REPORT_PEER_MSGS: Result<IntCounterVec> = try_create_int_counter_vec(
        "libp2p_report_peer_msgs_total",
        "Number of peer reports per msg",
        &["msg"]
    );
}

pub fn scrape_discovery_metrics() {
    let metrics =
        discv5::metrics::Metrics::from(discv5::Discv5::<discv5::DefaultProtocolId>::raw_metrics());
    set_float_gauge(&DISCOVERY_REQS, metrics.unsolicited_requests_per_second);
    set_gauge(&DISCOVERY_SESSIONS, metrics.active_sessions as i64);
    set_gauge_vec(&DISCOVERY_BYTES, &["inbound"], metrics.bytes_recv as i64);
    set_gauge_vec(&DISCOVERY_BYTES, &["outbound"], metrics.bytes_sent as i64);
}
