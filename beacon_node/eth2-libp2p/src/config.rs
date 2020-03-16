use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use enr::Enr;
use libp2p::discv5::Discv5ConfigBuilder;
use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder, GossipsubMessage, MessageId};
use libp2p::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

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

    /// Whether to allow discovery to automatically update the external address based on PONG
    /// responses.
    pub auto_update_enr_address: bool,

    /// An optional parameter to specify the discovery address as a DNS entry. Lighthouse will
    /// periodically check the DNS address and update the local ENR node record if the IP changes.
    ///
    /// Note: A value here will disable `auto_update_enr_address`.
    pub enr_dns_address: Option<String>,

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

    /// Discv5 configuration parameters.
    pub discv5_config: Discv5Config,

    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<Enr>,

    /// List of libp2p nodes to initially connect to.
    pub libp2p_nodes: Vec<Multiaddr>,

    /// Client version
    pub client_version: String,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<GossipTopic>,

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

        // The default topics that we will initially subscribe to
        let topics = vec![
            GossipTopic::new(GossipKind::BeaconBlock, GossipEncoding::SSZ),
            GossipTopic::new(GossipKind::BeaconAggregateAndProof, GossipEncoding::SSZ),
            GossipTopic::new(GossipKind::VoluntaryExit, GossipEncoding::SSZ),
            GossipTopic::new(GossipKind::ProposerSlashing, GossipEncoding::SSZ),
            GossipTopic::new(GossipKind::AttesterSlashing, GossipEncoding::SSZ),
        ];

        // The function used to generate a gossipsub message id
        // We use base64(SHA256(data)) for content addressing
        let gossip_message_id = |message: &GossipsubMessage| {
            MessageId(base64::encode_config(
                &Sha256::digest(&message.data),
                base64::URL_SAFE,
            ))
        };

        // gossipsub configuration
        // Note: The topics by default are sent as plain strings. Hashes are an optional
        // parameter.
        let gs_config = GossipsubConfigBuilder::new()
            .max_transmit_size(1_048_576)
            .heartbeat_interval(Duration::from_secs(20)) // TODO: Reduce for mainnet
            .manual_propagation() // require validation before propagation
            .no_source_id()
            .message_id_fn(gossip_message_id)
            .build();

        // discv5 configuration
        let discv5_config = Discv5ConfigBuilder::new()
            .request_timeout(Duration::from_secs(4))
            .request_retries(1)
            .enr_update(true) // update IP based on PONG responses
            .enr_peer_update_min(2) // prevents NAT's should be raised for mainnet
            .query_parallelism(5)
            .ip_limit(false) // limits /24 IP's in buckets. Enable for mainnet
            .ping_interval(Duration::from_secs(300))
            .build();

        Config {
            network_dir,
            listen_address: "127.0.0.1".parse().expect("valid ip address"),
            libp2p_port: 9000,
            discovery_port: 9000,
            enr_address: None,
            enr_udp_port: None,
            auto_update_enr_address: true,
            enr_dns_address: None,
            max_peers: 10,
            secret_key_hex: None,
            gs_config,
            discv5_config,
            boot_nodes: vec![],
            libp2p_nodes: vec![],
            client_version: version::version(),
            topics,
            propagation_percentage: None,
        }
    }
}
