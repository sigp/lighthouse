use crate::types::GossipKind;
use crate::{Enr, PeerIdSerialized};
use directory::{
    DEFAULT_BEACON_NODE_DIR, DEFAULT_HARDCODED_NETWORK, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR,
};
use discv5::{Discv5Config, Discv5ConfigBuilder};
use libp2p::gossipsub::{
    FastMessageId, GossipsubConfig, GossipsubConfigBuilder, GossipsubMessage, MessageId,
    RawGossipsubMessage, ValidationMode,
};
use libp2p::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use types::{ForkContext, ForkName};

pub const GOSSIP_MAX_SIZE: usize = 1_048_576;

// We treat uncompressed messages as invalid and never use the INVALID_SNAPPY_DOMAIN as in the
// specification. We leave it here for posterity.
// const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0, 0, 0, 0];
const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [1, 0, 0, 0];
pub const MESH_N_LOW: usize = 6;

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

    /// Import/aggregate all attestations recieved on subscribed subnets for the duration of the
    /// runtime.
    pub import_all_attestations: bool,

    /// Indicates if the user has set the network to be in private mode. Currently this
    /// prevents sending client identifying information over identify.
    pub private: bool,

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
            .join(DEFAULT_HARDCODED_NETWORK)
            .join(DEFAULT_BEACON_NODE_DIR)
            .join(DEFAULT_NETWORK_DIR);

        // Note: Using the default config here. Use `gossipsub_config` function for getting
        // Lighthouse specific configuration for gossipsub.
        let gs_config = GossipsubConfigBuilder::default()
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
            private: false,
            subscribe_all_subnets: false,
            import_all_attestations: false,
            topics: Vec::new(),
        }
    }
}

/// Return a Lighthouse specifi `GossipsubConfig` where the `message_id_fn` depends on the current fork.
pub fn gossipsub_config(fork_context: Arc<ForkContext>) -> GossipsubConfig {
    // The function used to generate a gossipsub message id
    // We use the first 8 bytes of SHA256(data) for content addressing
    let fast_gossip_message_id =
        |message: &RawGossipsubMessage| FastMessageId::from(&Sha256::digest(&message.data)[..8]);
    fn prefix(
        prefix: [u8; 4],
        message: &GossipsubMessage,
        fork_context: Arc<ForkContext>,
    ) -> Vec<u8> {
        let topic_bytes = message.topic.as_str().as_bytes();
        match fork_context.current_fork() {
            ForkName::Altair => {
                let topic_len_bytes = topic_bytes.len().to_le_bytes();
                let mut vec = Vec::with_capacity(
                    prefix.len() + topic_bytes.len() + topic_len_bytes.len() + message.data.len(),
                );
                vec.extend_from_slice(&prefix);
                vec.extend_from_slice(&topic_bytes.len().to_le_bytes());
                vec.extend_from_slice(topic_bytes);
                vec.extend_from_slice(&message.data);
                vec
            }
            ForkName::Base => {
                let mut vec = Vec::with_capacity(prefix.len() + message.data.len());
                vec.extend_from_slice(&prefix);
                vec.extend_from_slice(&message.data);
                vec
            }
        }
    }

    let gossip_message_id = move |message: &GossipsubMessage| {
        MessageId::from(
            &Sha256::digest(
                prefix(MESSAGE_DOMAIN_VALID_SNAPPY, &message, fork_context.clone()).as_slice(),
            )[..20],
        )
    };
    GossipsubConfigBuilder::default()
        .max_transmit_size(GOSSIP_MAX_SIZE)
        .heartbeat_interval(Duration::from_millis(700))
        .mesh_n(8)
        .mesh_n_low(MESH_N_LOW)
        .mesh_n_high(12)
        .gossip_lazy(6)
        .fanout_ttl(Duration::from_secs(60))
        .history_length(6)
        .max_messages_per_rpc(Some(10))
        .history_gossip(3)
        .validate_messages() // require validation before propagation
        .validation_mode(ValidationMode::Anonymous)
        // prevent duplicates for 550 heartbeats(700millis * 550) = 385 secs
        .duplicate_cache_time(Duration::from_secs(385))
        .message_id_fn(gossip_message_id)
        .fast_message_id_fn(fast_gossip_message_id)
        .allow_self_origin(true)
        .build()
        .expect("valid gossipsub configuration")
}
