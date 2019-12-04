use enr::Enr;
use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use libp2p::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// The gossipsub topic names.
// These constants form a topic name of the form /TOPIC_PREFIX/TOPIC/ENCODING_POSTFIX
// For example /eth2/beacon_block/ssz
pub const TOPIC_PREFIX: &str = "eth2";
pub const TOPIC_ENCODING_POSTFIX: &str = "ssz";
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";
pub const BEACON_ATTESTATION_TOPIC: &str = "beacon_attestation";
pub const VOLUNTARY_EXIT_TOPIC: &str = "voluntary_exit";
pub const PROPOSER_SLASHING_TOPIC: &str = "proposer_slashing";
pub const ATTESTER_SLASHING_TOPIC: &str = "attester_slashing";
pub const SHARD_TOPIC_PREFIX: &str = "shard";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
/// Network configuration for lighthouse.
pub struct Config {
    /// Data directory where node's keyfile is stored
    pub network_dir: PathBuf,

    /// IP address to listen on.
    pub listen_address: std::net::IpAddr,

    /// The TCP port that libp2p listens on.
    pub libp2p_port: u16,

    /// The address to broadcast to peers about which address we are listening on.
    pub discovery_address: std::net::IpAddr,

    /// UDP port that discovery listens on.
    pub discovery_port: u16,

    /// Target number of connected peers.
    pub max_peers: usize,

    /// A secp256k1 secret key, as bytes in ASCII-encoded hex.
    ///
    /// With or without `0x` prefix.
    #[serde(skip)]
    pub secret_key_hex: Option<String>,

    /// Gossipsub configuration parameters.
    #[serde(skip)]
    pub gs_config: GossipsubConfig,

    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<Enr>,

    /// List of libp2p nodes to initially connect to.
    pub libp2p_nodes: Vec<Multiaddr>,

    /// Client version
    pub client_version: String,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<String>,

    /// Introduces randomization in network propagation of messages. This should only be set for
    /// testing purposes and will likely be removed in future versions.
    // TODO: Remove this functionality for mainnet
    pub propagation_percentage: Option<u8>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        let mut network_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        network_dir.push(".lighthouse");
        network_dir.push("network");
        Config {
            network_dir,
            listen_address: "127.0.0.1".parse().expect("valid ip address"),
            libp2p_port: 9000,
            discovery_address: "127.0.0.1".parse().expect("valid ip address"),
            discovery_port: 9000,
            max_peers: 10,
            secret_key_hex: None,
            // Note: The topics by default are sent as plain strings. Hashes are an optional
            // parameter.
            gs_config: GossipsubConfigBuilder::new()
                .max_transmit_size(1_048_576)
                .heartbeat_interval(Duration::from_secs(20)) // TODO: Reduce for mainnet
                .manual_propagation(true) // require validation before propagation
                .build(),
            boot_nodes: vec![],
            libp2p_nodes: vec![],
            client_version: version::version(),
            topics: Vec::new(),
            propagation_percentage: None,
        }
    }
}
