use super::libp2p_core::Multiaddr;

pub struct NetworkConfig {
    pub config_dir: String,
    pub listen_multiaddr: Multiaddr,
}

impl NetworkConfig {
    pub fn default() -> Self{
        Self {
            config_dir: ".lighthouse".to_string(),
            listen_multiaddr: "/ip4/0.0.0.0/tcp/0"
                .parse::<Multiaddr>().unwrap()

        }
    }
}
