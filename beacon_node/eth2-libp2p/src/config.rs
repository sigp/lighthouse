use clap::ArgMatches;
use enr::Enr;
use libp2p::{
    gossipsub::{GossipsubConfig, GossipsubConfigBuilder},
    multiaddr::Multiaddr,
};
use serde_derive::{Deserialize, Serialize};
use std::time::Duration;

/// The beacon node topic string to subscribe to.
pub const BEACON_PUBSUB_TOPIC: &str = "beacon_block";
pub const BEACON_ATTESTATION_TOPIC: &str = "beacon_attestation";
//TODO: Implement shard subnets
pub const SHARD_TOPIC_PREFIX: &str = "shard";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
/// Network configuration for lighthouse.
pub struct Config {
    /// IP address to listen on.
    pub listen_addresses: Vec<Multiaddr>,

    /// Specifies the IP address that the discovery protocol will listen on.
    pub discovery_address: std::net::IpAddr,

    /// UDP port that discovery listens on.
    pub discovery_port: u16,

    /// Target number of connected peers.
    pub max_peers: usize,

    /// Gossipsub configuration parameters.
    #[serde(skip)]
    pub gs_config: GossipsubConfig,

    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<Enr>,

    /// Client version
    pub client_version: String,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<String>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        Config {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/9000".parse().expect("vaild multiaddr")],
            discovery_address: "0.0.0.0".parse().expect("valid ip address"),
            discovery_port: 9000,
            max_peers: 10,
            //TODO: Set realistic values for production
            gs_config: GossipsubConfigBuilder::new()
                .max_gossip_size(4_000_000)
                .inactivity_timeout(Duration::from_secs(90))
                .heartbeat_interval(Duration::from_secs(20))
                .build(),
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

    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), String> {
        if let Some(listen_address_str) = args.value_of("listen-address") {
            self.listen_addresses = listen_address_str
                .split(',')
                .map(|a| {
                    a.parse::<Multiaddr>()
                        .map_err(|_| format!("Invalid Listen address: {:?}", a))
                })
                .collect::<Result<Vec<Multiaddr>, _>>()?;
        }

        if let Some(max_peers_str) = args.value_of("maxpeers") {
            self.max_peers = max_peers_str
                .parse::<usize>()
                .map_err(|_| format!("Invalid number of max peers: {}", max_peers_str))?;
        }

        if let Some(discovery_address_str) = args.value_of("disc-listen-address") {
            self.discovery_address = discovery_address_str
                .parse::<std::net::IpAddr>()
                .map_err(|_| format!("Invalid discovery address: {:?}", discovery_address_str))?;
        }

        if let Some(boot_enr_str) = args.value_of("boot-nodes") {
            self.boot_nodes = boot_enr_str
                .split(',')
                .map(|enr| enr.parse().map_err(|_| format!("Invalid ENR: {}", enr)))
                .collect::<Result<Vec<Enr>, _>>()?;
        }

        if let Some(disc_port_str) = args.value_of("disc-port") {
            self.discovery_port = disc_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", disc_port_str))?;
        }

        Ok(())
    }
}
