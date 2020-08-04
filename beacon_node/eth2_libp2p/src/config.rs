use crate::types::GossipKind;
use crate::Enr;
use discv5::{Discv5Config, Discv5ConfigBuilder};
use libp2p::gossipsub::{
    GossipsubConfig, GossipsubConfigBuilder, GossipsubMessage, MessageId, ValidationMode,
};
use libp2p::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

pub const GOSSIP_MAX_SIZE: usize = 1_048_576;

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

    /// UDP port that discovery listens on.
    pub discovery_port: u16,

    /// The address to broadcast to peers about which address we are listening on. None indicates
    /// that no discovery address has been set in the CLI args.
    pub enr_address: Option<std::net::IpAddr>,

    /// The udp port to broadcast to peers in order to reach back for discovery.
    pub enr_udp_port: Option<u16>,

    /// The tcp port to broadcast to peers in order to reach back for libp2p services.
    pub enr_tcp_port: Option<u16>,

    /// Target number of connected peers.
    pub target_peers: usize,

    /// Gossipsub configuration parameters.
    #[serde(skip)]
    pub gs_config: GossipsubConfig,

    /// Discv5 configuration parameters.
    #[serde(skip)]
    pub discv5_config: Discv5Config,

    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<Enr>,

    /// List of libp2p nodes to initially connect to.
    pub libp2p_nodes: Vec<Multiaddr>,

    /// Client version
    pub client_version: String,

    /// Disables the discovery protocol from starting.
    pub disable_discovery: bool,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<GossipKind>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        let mut network_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        network_dir.push(".lighthouse");
        network_dir.push("network");

        // The default topics that we will initially subscribe to
        let topics = vec![
            GossipKind::BeaconBlock,
            GossipKind::BeaconAggregateAndProof,
            GossipKind::VoluntaryExit,
            GossipKind::ProposerSlashing,
            GossipKind::AttesterSlashing,
        ];

        // The function used to generate a gossipsub message id
        // We use base64(SHA256(data)) for content addressing
        let gossip_message_id = |message: &GossipsubMessage| {
            MessageId::from(base64::encode_config(
                &Sha256::digest(&message.data),
                base64::URL_SAFE_NO_PAD,
            ))
        };

        // gossipsub configuration
        // Note: The topics by default are sent as plain strings. Hashes are an optional
        // parameter.
        let gs_config = GossipsubConfigBuilder::new()
            .max_transmit_size(GOSSIP_MAX_SIZE)
            .heartbeat_interval(Duration::from_secs(1))
            .validate_messages() // require validation before propagation
            .validation_mode(ValidationMode::Permissive)
            // Prevent duplicates by caching messages from an epoch + 1 slot amount of time (33*12)
            .duplicate_cache_time(Duration::from_secs(396))
            .message_id_fn(gossip_message_id)
            .build();

        // discv5 configuration
        let discv5_config = Discv5ConfigBuilder::new()
            .enable_packet_filter()
            .session_cache_capacity(1000)
            .request_timeout(Duration::from_secs(4))
            .request_retries(1)
            .enr_peer_update_min(10)
            .query_parallelism(5)
            .query_timeout(Duration::from_secs(30))
            .query_peer_timeout(Duration::from_secs(2))
            .ip_limit() // limits /24 IP's in buckets.
            .ping_interval(Duration::from_secs(300))
            .build();

        // NOTE: Some of these get overridden by the corresponding CLI default values.
        Config {
            network_dir,
            listen_address: "0.0.0.0".parse().expect("valid ip address"),
            libp2p_port: 9000,
            discovery_port: 9000,
            enr_address: None,
            enr_udp_port: None,
            enr_tcp_port: None,
            target_peers: 50,
            gs_config,
            discv5_config,
            boot_nodes: vec![],
            libp2p_nodes: vec![],
            client_version: lighthouse_version::version_with_platform(),
            disable_discovery: false,
            topics,
        }
    }
}
