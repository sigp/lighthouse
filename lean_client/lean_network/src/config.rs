/// Network configuration for the lean client
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Port to listen on for network connections
    pub listen_port: u16,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 9000,
            bootstrap_nodes: vec![],
        }
    }
}

impl NetworkConfig {
    pub fn new(listen_port: u16) -> Self {
        Self {
            listen_port,
            bootstrap_nodes: vec![],
        }
    }

    pub fn with_bootstrap_nodes(mut self, bootstrap_nodes: Vec<String>) -> Self {
        self.bootstrap_nodes = bootstrap_nodes;
        self
    }
}
