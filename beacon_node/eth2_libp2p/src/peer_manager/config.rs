/* CONSTANTS */
/// The heartbeat performs regular updates such as updating reputations and performing discovery
/// requests. This defines the interval in seconds.
pub const HEARTBEAT_INTERVAL: u64 = 30;

/// A fraction of `PeerManager::target_peers` that we allow to connect to us in excess of
/// `PeerManager::target_peers`. For clarity, if `PeerManager::target_peers` is 50 and
/// PEER_EXCESS_FACTOR = 0.1 we allow 10% more nodes, i.e 55.
pub const PEER_EXCESS_FACTOR: f32 = 0.1;

/// A fraction of `PeerManager::target_peers` that need to be outbound-only connections.
pub const MIN_OUTBOUND_ONLY_FACTOR: f32 = 0.3;

/// The fraction of extra peers beyond the PEER_EXCESS_FACTOR that we allow us to dial for when
/// requiring subnet peers. More specifically, if our target peer limit is 50, and our excess peer
/// limit is 55, and we are at 55 peers, the following parameter provisions a few more slots of
/// dialing priority peers we need for validator duties.
pub const PRIORITY_PEER_EXCESS: f32 = 0.05;

/// Relative factor of peers that are allowed to have a negative gossipsub score without penalizing
/// them in lighthouse.
pub const ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR: f32 = 0.1;

/* Defaults for configurable values */

/// The time in seconds between re-status's peers.
pub const DEFAULT_STATUS_INTERVAL: u64 = 300;

/// Default ping interval for outbound connections, in seconds.
pub const DEFAULT_PING_INTERVAL_OUTBOUND: u64 = 15;

/// The interval for inbound connections.
pub const DEFAULT_PING_INTERVAL_INBOUND: u64 = 20;

/// Default number of peers to connect to.
pub const DEFAULT_TARGET_PEERS: usize = 50;

/// Configurations for the PeerManager.
#[derive(Debug)]
pub struct Config {
    /* Peer count related configurations */
    /// Wheather discovery is enabled.
    pub discovery_enabled: bool,
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
            target_peer_count: DEFAULT_TARGET_PEERS,
            status_interval: DEFAULT_STATUS_INTERVAL,
            ping_interval_inbound: DEFAULT_PING_INTERVAL_INBOUND,
            ping_interval_outbound: DEFAULT_PING_INTERVAL_OUTBOUND,
        }
    }
}
