use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const LISTEN_ADDR: &str = "127.0.0.1";

pub const fn listen_port() -> u16 {
    5059
}
fn listen_addr() -> IpAddr {
    LISTEN_ADDR.parse().expect("Server address is not valid")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "listen_addr")]
    pub listen_addr: IpAddr,
    #[serde(default = "listen_port")]
    pub listen_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: listen_addr(),
            listen_port: listen_port(),
        }
    }
}
