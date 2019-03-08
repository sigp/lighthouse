use crate::Multiaddr;
use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use libp2p::secio;
use std::fmt;

#[derive(Clone)]
/// Network configuration for lighthouse.
pub struct NetworkConfig {
    //TODO: stubbing networking initial params, change in the future
    /// IP address to listen on.
    pub listen_addresses: Vec<Multiaddr>,
    /// Listen port UDP/TCP.
    pub listen_port: u16,
    /// Gossipsub configuration parameters.
    pub gs_config: GossipsubConfig,
    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<Multiaddr>,
    /// Peer key related to this nodes PeerId.
    pub local_private_key: secio::SecioKeyPair,
    /// Client version
    pub client_version: String,
}

impl Default for NetworkConfig {
    /// Generate a default network configuration.
    fn default() -> Self {
        // TODO: Currently using ed25519 key pairs. Wire protocol specifies RSA. Waiting for this
        // PR to be merged to generate RSA keys: https://github.com/briansmith/ring/pull/733
        NetworkConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/9000"
                .parse()
                .expect("is a correct multi-address")],
            listen_port: 9000,
            gs_config: GossipsubConfigBuilder::new().build(),
            boot_nodes: Vec::new(),
            local_private_key: secio::SecioKeyPair::ed25519_generated().unwrap(),
            client_version: version::version(),
        }
    }
}

impl NetworkConfig {
    pub fn new(boot_nodes: Vec<Multiaddr>) -> Self {
        let mut conf = NetworkConfig::default();
        conf.boot_nodes = boot_nodes;

        conf
    }
}

impl fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NetworkConfig: listen_addresses: {:?}, listen_port: {:?}, gs_config: {:?}, boot_nodes: {:?}, local_private_key: <Secio-PubKey {:?}>, client_version: {:?}", self.listen_addresses, self.listen_port, self.gs_config, self.boot_nodes, self.local_private_key.to_public_key(), self.client_version)
    }
}
