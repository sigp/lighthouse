pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref ADDRESS_UPDATE_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_address_update_count",
        "Count of libp2p socked updated events (when our view of our IP address has changed)"
    );
    pub static ref PEER_CONNECT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_connect_count",
        "Count of libp2p peer connect events (not the current number of connected peers)"
    );
    pub static ref PEER_DISCONNECT_COUNT: Result<IntCounter> = try_create_int_counter(
        "libp2p_peer_disconnect_count",
        "Count of libp2p peer disconnect events"
    );
}
