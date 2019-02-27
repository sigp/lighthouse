use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use std::net::IpAddr;
use version;

#[derive(Debug, Clone)]
/// Network configuration for lighthouse.
pub struct NetworkConfiguration {
    //TODO: stubbing networking initial params, change in the future
    /// IP address to listen on.
    pub listen_address: Option<IpAddr>,
    /// Listen port UDP/TCP.
    pub listen_port: Option<u16>,
    /// Gossipsub configuration parameters.
    pub gs_config: GossipsubConfig,
    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<String>,
    /// Client version
    pub client_version: String,
    //TODO: more to be added
}

impl Default for NetworkConfiguration {
    /// Generate a default network configuration.
    fn default() -> Self {
        NetworkConfiguration {
            listen_address: None,
            listen_port: None,
            gs_config: GossipsubConfigBuilder::new().build(),
            boot_nodes: Vec::new(),
            client_version: version::version(),
        }
    }
}

impl NetworkConfiguration {
    pub fn new() -> Self {
        NetworkConfiguration::default()
    }
}
