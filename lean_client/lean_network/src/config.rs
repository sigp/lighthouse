/// Network configuration for the lean client
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Port to listen on for network connections
    pub listen_port: u16,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Raw libp2p private key bytes (secp256k1). Optional for generated identity.
    pub node_key: Option<Vec<u8>>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 9000,
            bootstrap_nodes: vec![],
            node_key: None,
        }
    }
}

impl NetworkConfig {
    pub fn new(listen_port: u16) -> Self {
        Self {
            listen_port,
            bootstrap_nodes: vec![],
            node_key: None,
        }
    }

    pub fn with_bootstrap_nodes(mut self, bootstrap_nodes: Vec<String>) -> Self {
        self.bootstrap_nodes = bootstrap_nodes;
        self
    }

    pub fn with_node_key(mut self, node_key: Vec<u8>) -> Self {
        self.node_key = Some(node_key);
        self
    }
}
