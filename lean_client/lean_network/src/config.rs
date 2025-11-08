/// Network configuration for the lean client
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Port to listen on for network connections
    pub listen_port: u16,
    /// Maximum number of peers to connect to
    pub max_peers: usize,
    /// Whether to enable peer discovery
    pub enable_discovery: bool,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 9000,
            max_peers: 50,
            enable_discovery: true,
            bootstrap_nodes: vec![],
        }
    }
}

impl NetworkConfig {
    /// Create a new network configuration
    pub fn new(listen_port: u16) -> Self {
        Self {
            listen_port,
            max_peers: 50,
            enable_discovery: true,
            bootstrap_nodes: vec![],
        }
    }

    /// Set the maximum number of peers
    pub fn with_max_peers(mut self, max_peers: usize) -> Self {
        self.max_peers = max_peers;
        self
    }

    /// Enable or disable peer discovery
    pub fn with_discovery(mut self, enable_discovery: bool) -> Self {
        self.enable_discovery = enable_discovery;
        self
    }

    /// Set bootstrap nodes
    pub fn with_bootstrap_nodes(mut self, bootstrap_nodes: Vec<String>) -> Self {
        self.bootstrap_nodes = bootstrap_nodes;
        self
    }
}
