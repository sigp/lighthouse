use clap::ArgMatches;
use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use libp2p::multiaddr::{Error as MultiaddrError, Multiaddr};
use serde_derive::{Deserialize, Serialize};
use std::time::Duration;

/// The beacon node topic string to subscribe to.
pub const BEACON_PUBSUB_TOPIC: &str = "beacon_node";
pub const SHARD_TOPIC_PREFIX: &str = "attestations"; // single topic for all attestation for the moment.

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
    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<String>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        Config {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/9000".to_string()],
            gs_config: GossipsubConfigBuilder::new()
                .max_gossip_size(4_000_000)
                .inactivity_timeout(Duration::from_secs(90))
                .heartbeat_interval(Duration::from_secs(20))
                .build(),
            identify_config: IdentifyConfig::default(),
            boot_nodes: vec![],
            client_version: version::version(),
            topics: Vec::new(),
        }
    }
}

/// Generates a default Config.
impl Config {
    pub fn new() -> Self {
        Config::default()
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

/// Creates a standard network config from a chain_id.
///
/// This creates specified network parameters for each chain type.
impl From<ChainType> for Config {
    fn from(chain_type: ChainType) -> Self {
        match chain_type {
            ChainType::Foundation => Config::default(),

            ChainType::LighthouseTestnet => {
                let boot_nodes = vec!["/ip4/127.0.0.1/tcp/9000"
                    .parse()
                    .expect("correct multiaddr")];
                Self {
                    boot_nodes,
                    ..Config::default()
                }
            }

            ChainType::Other => Config::default(),
        }
    }
}

pub enum ChainType {
    Foundation,
    LighthouseTestnet,
    Other,
}

/// Maps a chain id to a ChainType.
impl From<u8> for ChainType {
    fn from(chain_id: u8) -> Self {
        match chain_id {
            1 => ChainType::Foundation,
            2 => ChainType::LighthouseTestnet,
            _ => ChainType::Other,
        }
    }
}
