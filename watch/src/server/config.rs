use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const SERVER_ADDR: &str = "127.0.0.1";

pub const fn server_port() -> u16 {
    5059
}
fn server_addr() -> Ipv4Addr {
    SERVER_ADDR.parse().expect("Server address is not valid")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "server_addr")]
    pub server_listen_addr: Ipv4Addr,
    #[serde(default = "server_port")]
    pub server_listen_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_listen_addr: server_addr(),
            server_listen_port: server_port(),
        }
    }
}
