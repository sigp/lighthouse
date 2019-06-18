use clap::ArgMatches;
use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use serde_derive::{Deserialize, Serialize};
use types::multiaddr::{Error as MultiaddrError, Multiaddr};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
/// Network configuration for lighthouse.
pub struct Config {
    /// IP address to listen on.
    listen_addresses: Vec<String>,
    /// Gossipsub configuration parameters.
    #[serde(skip)]
    pub gs_config: GossipsubConfig,
    /// Configuration parameters for node identification protocol.
    #[serde(skip)]
    pub identify_config: IdentifyConfig,
    /// List of nodes to initially connect to.
    boot_nodes: Vec<String>,
    /// Client version
    pub client_version: String,
    /// List of topics to subscribe to as strings
    pub topics: Vec<String>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        Config {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/9000".to_string()],
            gs_config: GossipsubConfigBuilder::new()
                .max_gossip_size(4_000_000)
                .build(),
            identify_config: IdentifyConfig::default(),
            boot_nodes: vec![],
            client_version: version::version(),
            topics: vec![String::from("beacon_chain")],
        }
    }
}

impl Config {
    pub fn new(boot_nodes: Vec<String>) -> Self {
        let mut conf = Config::default();
        conf.boot_nodes = boot_nodes;

        conf
    }

    pub fn listen_addresses(&self) -> Result<Vec<Multiaddr>, MultiaddrError> {
        self.listen_addresses.iter().map(|s| s.parse()).collect()
    }

    pub fn boot_nodes(&self) -> Result<Vec<Multiaddr>, MultiaddrError> {
        self.boot_nodes.iter().map(|s| s.parse()).collect()
    }

    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), &'static str> {
        if let Some(listen_address_str) = args.value_of("listen-address") {
            let listen_addresses = listen_address_str.split(',').map(Into::into).collect();
            self.listen_addresses = listen_addresses;
        }

        if let Some(boot_addresses_str) = args.value_of("boot-nodes") {
            let boot_addresses = boot_addresses_str.split(',').map(Into::into).collect();
            self.boot_nodes = boot_addresses;
        }

        Ok(())
    }
}

/// The configuration parameters for the Identify protocol
#[derive(Debug, Clone)]
pub struct IdentifyConfig {
    /// The protocol version to listen on.
    pub version: String,
    /// The client's name and version for identification.
    pub user_agent: String,
}

impl Default for IdentifyConfig {
    fn default() -> Self {
        Self {
            version: "/eth/serenity/1.0".to_string(),
            user_agent: version::version(),
        }
    }
}
