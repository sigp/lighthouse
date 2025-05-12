/// Every configuration needed for Mallory.
#[derive(Debug, Clone)]
pub struct MalloryConfig {
    /* Peer manager stuff */
    /// Ping inbound peers this often (in seconds) instead of the default `PING_INTERVAL_INBOUND`.
    pub inbound_peers_ping: Option<u64>,
    /// Ping outbound peers this often (in seconds) instead of the default `PING_INTERVAL_OUTBOUND`.
    pub outbound_peers_ping: Option<u64>,
    /// Status peers this often (in seconds) instead of the default `STATUS_INTERVAL`.
    pub status_interval: Option<u64>,

    /* RPC stuff */
    /// Duration in seconds after which an inbound connection with a peer times out instead of the
    /// default `RESPONSE_TIMEOUT`.
    pub inbound_rpc_timeout: Option<u64>,

    /// Duration in seconds after which an outbound connection with a peer times out instead of the
    /// default `RESPONSE_TIMEOUT`.
    pub outbound_rpc_timeout: Option<u64>,

    /* Behaviour Stuff */
    // Allow the user to handle a ping request
    pub user_handle_ping: bool,
}

impl Default for MalloryConfig {
    fn default() -> Self {
        Self {
            inbound_peers_ping: None,
            outbound_peers_ping: None,
            status_interval: None,
            inbound_rpc_timeout: None,
            outbound_rpc_timeout: None,
            user_handle_ping: false,
        }
    }
}
