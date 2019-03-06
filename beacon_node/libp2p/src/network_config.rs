use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use libp2p::secio;
use std::fmt;
use std::net::IpAddr;

#[derive(Clone)]
/// Network configuration for lighthouse.
pub struct NetworkConfig {
    //TODO: stubbing networking initial params, change in the future
    /// IP address to listen on.
    pub listen_addresses: Vec<IpAddr>,
    /// Listen port UDP/TCP.
    pub listen_port: u16,
    /// Gossipsub configuration parameters.
    pub gs_config: GossipsubConfig,
    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<IpAddr>,
    /// Peer key related to this nodes PeerId.
    pub local_private_key: secio::SecioKeyPair,
    /// Client version
    pub client_version: String,
}

impl Default for NetworkConfig {
    /// Generate a default network configuration.
    fn default() -> Self {
        // hard-coded defaults
        let bootnodes = ["127.0.0.1"];
        let default_port = 9000;

        // TODO: Currently using ed25519 key pairs. Wire protocol specifies RSA. Waiting for this
        // PR to be merged to generate RSA keys: https://github.com/briansmith/ring/pull/733

        NetworkConfig {
            listen_addresses: vec!["127.0.0.1".parse().expect("correct IP address")],
            listen_port: default_port,
            gs_config: GossipsubConfigBuilder::new().build(),
            boot_nodes: bootnodes
                .iter()
                .map(|s| s.parse().expect("Bootnodes must be IP addresses"))
                .collect(),
            local_private_key: secio::SecioKeyPair::ed25519_generated().unwrap(),
            client_version: version::version(),
        }
    }
}

impl NetworkConfig {
    pub fn new() -> Self {
        NetworkConfig::default()
    }
}

impl fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NetworkConfig: listen_addresses: {:?}, listen_port: {:?}, gs_config: {:?}, boot_nodes: {:?}, local_private_key: <Secio-PubKey {:?}>, client_version: {:?}", self.listen_addresses, self.listen_port, self.gs_config, self.boot_nodes, self.local_private_key.to_public_key(), self.client_version)
    }
}
