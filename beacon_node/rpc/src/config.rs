use std::net::Ipv4Addr;

/// RPC Configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Enable the RPC server.
    pub enabled: bool,
    /// The IPv4 address the RPC will listen on.
    pub listen_address: Ipv4Addr,
    /// The port the RPC will listen on.
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: false, // rpc disabled by default
            listen_address: Ipv4Addr::new(127, 0, 0, 1),
            port: 5051,
        }
    }
}
