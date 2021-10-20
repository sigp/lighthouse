pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref ADDRESS_UPDATE_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_address_update_total",
        "Count of libp2p socked updated events (when our view of our IP address has changed)"
    );
    pub static ref PEERS_CONNECTED: Result<IntGauge> = try_create_int_gauge(
        "libp2p_peer_connected_peers_total",
        "Count of libp2p peers currently connected"
    );
    pub static ref PEERS_CONNECTED_INTEROP: Result<IntGauge> =
        try_create_int_gauge("libp2p_peers", "Count of libp2p peers currently connected");
    pub static ref PEER_CONNECT_EVENT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_connect_event_total",
        "Count of libp2p peer connect events (not the current number of connected peers)"
    );
    pub static ref PEER_DISCONNECT_EVENT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_disconnect_event_total",
        "Count of libp2p peer disconnect events"
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
    pub static ref DISCOVERY_REQS_IP: Result<GaugeVec> = try_create_float_gauge_vec(
        "discovery_reqs_per_ip",
        "Unsolicited discovery requests per ip per second",
        &["Addresses"]
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
}

pub fn scrape_discovery_metrics() {
    let metrics = discv5::metrics::Metrics::from(discv5::Discv5::raw_metrics());

    set_float_gauge(&DISCOVERY_REQS, metrics.unsolicited_requests_per_second);

    set_gauge(&DISCOVERY_SESSIONS, metrics.active_sessions as i64);

    let process_gauge_vec = |gauge: &Result<GaugeVec>, metrics: discv5::metrics::Metrics| {
        if let Ok(gauge_vec) = gauge {
            gauge_vec.reset();
            for (ip, value) in metrics.requests_per_ip_per_second.iter() {
                if let Ok(metric) = gauge_vec.get_metric_with_label_values(&[&format!("{:?}", ip)])
                {
                    metric.set(*value);
                }
            }
        }
    };

    process_gauge_vec(&DISCOVERY_REQS_IP, metrics);
}
