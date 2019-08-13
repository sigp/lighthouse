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
    pub static ref PEER_CONNECT_EVENT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_connect_event_total",
        "Count of libp2p peer connect events (not the current number of connected peers)"
    );
    pub static ref PEER_DISCONNECT_EVENT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_disconnect_event_total",
        "Count of libp2p peer disconnect events"
    );
}
