use crate::types::{GossipKind, MessageData};
use crate::{Enr, PeerIdSerialized};
use directory::{
    DEFAULT_BEACON_NODE_DIR, DEFAULT_HARDCODED_TESTNET, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR,
};
use discv5::{Discv5Config, Discv5ConfigBuilder};
use libp2p::gossipsub::{
    FastMessageId, GenericGossipsubConfig, GenericGossipsubConfigBuilder, GenericGossipsubMessage,
    MessageId, RawGossipsubMessage, ValidationMode,
};
use libp2p::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

pub const GOSSIP_MAX_SIZE: usize = 1_048_576;
const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0, 0, 0, 0];
const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [1, 0, 0, 0];
pub const MESH_N_LOW: usize = 6;

pub type GossipsubConfig = GenericGossipsubConfig<MessageData>;
pub type GossipsubConfigBuilder = GenericGossipsubConfigBuilder<MessageData>;
pub type GossipsubMessage = GenericGossipsubMessage<MessageData>;

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
    pub boot_nodes_enr: Vec<Enr>,

    /// List of nodes to initially connect to, on Multiaddr format.
    pub boot_nodes_multiaddr: Vec<Multiaddr>,

    /// List of libp2p nodes to initially connect to.
    pub libp2p_nodes: Vec<Multiaddr>,

    /// List of trusted libp2p nodes which are not scored.
    pub trusted_peers: Vec<PeerIdSerialized>,

    /// Client version
    pub client_version: String,

    /// Disables the discovery protocol from starting.
    pub disable_discovery: bool,

    /// Attempt to construct external port mappings with UPnP.
    pub upnp_enabled: bool,

    /// Subscribe to all subnets for the duration of the runtime.
    pub subscribe_all_subnets: bool,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<GossipKind>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        // WARNING: this directory default should be always overwritten with parameters
        // from cli for specific networks.
        let network_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(DEFAULT_HARDCODED_TESTNET)
            .join(DEFAULT_BEACON_NODE_DIR)
            .join(DEFAULT_NETWORK_DIR);

        // The function used to generate a gossipsub message id
        // We use the first 8 bytes of SHA256(data) for content addressing
        let fast_gossip_message_id =
            |message: &RawGossipsubMessage| FastMessageId::from(&Sha256::digest(&message.data)[..]);

        fn prefix(prefix: [u8; 4], data: &[u8]) -> Vec<u8> {
            prefix
                .to_vec()
                .into_iter()
                .chain(data.iter().cloned())
                .collect()
        }

        let gossip_message_id = |message: &GossipsubMessage| {
            MessageId::from(
                &Sha256::digest(
                    {
                        match &message.data.decompressed {
                            Ok(decompressed) => prefix(MESSAGE_DOMAIN_VALID_SNAPPY, decompressed),
                            _ => prefix(MESSAGE_DOMAIN_INVALID_SNAPPY, &message.data.raw),
                        }
                    }
                    .as_slice(),
                )[..20],
            )
        };

        // gossipsub configuration
        // Note: The topics by default are sent as plain strings. Hashes are an optional
        // parameter.
        let gs_config = GossipsubConfigBuilder::new()
            .max_transmit_size(GOSSIP_MAX_SIZE)
            .heartbeat_interval(Duration::from_millis(700))
            .mesh_n(8)
            .mesh_n_low(MESH_N_LOW)
            .mesh_n_high(12)
            .gossip_lazy(6)
            .fanout_ttl(Duration::from_secs(60))
            .history_length(6)
            .history_gossip(3)
            .validate_messages() // require validation before propagation
            .validation_mode(ValidationMode::Anonymous)
            // prevent duplicates for 550 heartbeats(700millis * 550) = 385 secs
            .duplicate_cache_time(Duration::from_secs(385))
            .message_id_fn(gossip_message_id)
            .fast_message_id_fn(fast_gossip_message_id)
            .allow_self_origin(true)
            .build()
            .expect("valid gossipsub configuration");

        // discv5 configuration
        let discv5_config = Discv5ConfigBuilder::new()
            .enable_packet_filter()
            .session_cache_capacity(1000)
            .request_timeout(Duration::from_secs(1))
            .query_peer_timeout(Duration::from_secs(2))
            .query_timeout(Duration::from_secs(30))
            .request_retries(1)
            .enr_peer_update_min(10)
            .query_parallelism(5)
            .disable_report_discovered_peers()
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
            boot_nodes_enr: vec![],
            boot_nodes_multiaddr: vec![],
            libp2p_nodes: vec![],
            trusted_peers: vec![],
            client_version: lighthouse_version::version_with_platform(),
            disable_discovery: false,
            upnp_enabled: true,
            subscribe_all_subnets: false,
            topics: Vec::new(),
        }
    }
}
