use std::env; 
use std::path::PathBuf; 

use super::libp2p_core::Multiaddr;

#[derive(Clone)]
pub struct NetworkConfig {
    pub data_dir: PathBuf,
    pub listen_multiaddr: Multiaddr,
}

const DEFAULT_LIGHTHOUSE_DIR: &str = ".lighthouse";

impl NetworkConfig {
    pub fn default() -> Self{
        let data_dir = {
            let home = env::home_dir()
                .expect("Unable to determine home dir.");
            home.join(DEFAULT_LIGHTHOUSE_DIR)
        };
        Self {
            data_dir,
            listen_multiaddr: NetworkConfig::multiaddr_on_port("0")

        }
    }

    /// Return a TCP multiaddress on 0.0.0.0 for a given port.
    pub fn multiaddr_on_port(port: &str) -> Multiaddr {
        return format!("/ip4/0.0.0.0/tcp/{}", port)
            .parse::<Multiaddr>().unwrap()
    }
}
