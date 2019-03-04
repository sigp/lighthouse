use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use std::net::IpAddr;
use version;

#[derive(Debug, Clone)]
/// Network configuration for lighthouse.
pub struct NetworkConfig {
    //TODO: stubbing networking initial params, change in the future
    /// IP address to listen on.
    pub listen_addresses: Option<Vec<IpAddr>>,
    /// Listen port UDP/TCP.
    pub listen_port: Option<u16>,
    /// Gossipsub configuration parameters.
    pub gs_config: GossipsubConfig,
    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<String>,
    /// Client version
    pub client_version: String,
}

impl Default for NetworkConfig {
    /// Generate a default network configuration.
    fn default() -> Self {
        NetworkConfig {
            listen_addresses: None,
            listen_port: None,
            gs_config: GossipsubConfigBuilder::new().build(),
            boot_nodes: Vec::new(),
            client_version: version::version(),
        }
    }
}

impl NetworkConfig {
    pub fn new() -> Self {
        NetworkConfig::default()
    }
}
