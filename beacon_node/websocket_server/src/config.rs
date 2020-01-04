use serde_derive::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    /// The IPv4 address the REST API HTTP server will listen on.
    pub listen_address: Ipv4Addr,
    /// The port the REST API HTTP server will listen on.
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: false,
            listen_address: Ipv4Addr::new(127, 0, 0, 1),
            port: 5053,
        }
    }
}
