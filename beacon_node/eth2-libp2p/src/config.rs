use crate::Multiaddr;
use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};

#[derive(Clone, Debug)]
/// Network configuration for lighthouse.
pub struct Config {
    //TODO: stubbing networking initial params, change in the future
    /// IP address to listen on.
    pub listen_addresses: Vec<Multiaddr>,
    /// Listen port UDP/TCP.
    pub listen_port: u16,
    /// Gossipsub configuration parameters.
    pub gs_config: GossipsubConfig,
    /// Configuration parameters for node identification protocol.
    pub identify_config: IdentifyConfig,
    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<Multiaddr>,
    /// Client version
    pub client_version: String,
    /// List of topics to subscribe to as strings
    pub topics: Vec<String>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        Config {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/9000"
                .parse()
                .expect("is a correct multi-address")],
            listen_port: 9000,
            gs_config: GossipsubConfigBuilder::new()
                .max_gossip_size(4_000_000)
                .build(),
            identify_config: IdentifyConfig::default(),
            boot_nodes: Vec::new(),
            client_version: version::version(),
            topics: vec![String::from("beacon_chain")],
        }
    }
}

impl Config {
    pub fn new(boot_nodes: Vec<Multiaddr>) -> Self {
        let mut conf = Config::default();
        conf.boot_nodes = boot_nodes;

        conf
    }
}

/// The configuration parameters for the Identify protocol
#[derive(Debug, Clone)]
pub struct IdentifyConfig {
    /// The protocol version to listen on.
    pub version: String,
    /// The client's name and version for identification.
    pub user_agent: String,
}

impl Default for IdentifyConfig {
    fn default() -> Self {
        Self {
            version: "/eth/serenity/1.0".to_string(),
            user_agent: version::version(),
        }
    }
}
