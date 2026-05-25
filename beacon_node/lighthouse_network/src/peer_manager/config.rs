/// The time in seconds between re-status's peers.
pub const DEFAULT_STATUS_INTERVAL: u64 = 300;

/// Default ping interval for outbound connections, in seconds.
pub const DEFAULT_PING_INTERVAL_OUTBOUND: u64 = 15;

/// Default interval for inbound connections.
pub const DEFAULT_PING_INTERVAL_INBOUND: u64 = 20;

/// Default number of peers to connect to.
pub const DEFAULT_TARGET_PEERS: usize = 200;

/// Configurations for the PeerManager.
#[derive(Debug)]
pub struct Config {
    /* Peer count related configurations */
    /// Whether discovery is enabled.
    pub discovery_enabled: bool,
    /// Whether metrics are enabled.
    pub metrics_enabled: bool,
    /// Whether quic is enabled.
    pub quic_enabled: bool,
    /// Target number of peers to connect to.
    pub target_peer_count: usize,

    /* RPC related configurations */
    /// Time in seconds between status requests sent to peers.
    pub status_interval: u64,
    /// The time in seconds between PING events. We do not send a ping if the other peer has PING'd
    /// us within this time frame (Seconds). This is asymmetric to avoid simultaneous pings. This
    /// interval applies to inbound connections: those in which we are not the dialer.
    pub ping_interval_inbound: u64,
    /// Interval between PING events for peers dialed by us.
    pub ping_interval_outbound: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            discovery_enabled: true,
            metrics_enabled: false,
            quic_enabled: true,
            target_peer_count: DEFAULT_TARGET_PEERS,
            status_interval: DEFAULT_STATUS_INTERVAL,
            ping_interval_inbound: DEFAULT_PING_INTERVAL_INBOUND,
            ping_interval_outbound: DEFAULT_PING_INTERVAL_OUTBOUND,
        }
    }
}
