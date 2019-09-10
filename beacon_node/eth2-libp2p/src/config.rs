use clap::ArgMatches;
use enr::Enr;
use libp2p::gossipsub::{GossipsubConfig, GossipsubConfigBuilder};
use libp2p::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// The gossipsub topic names.
// These constants form a topic name of the form /TOPIC_PREFIX/TOPIC/ENCODING_POSTFIX
// For example /eth2/beacon_block/ssz
pub const TOPIC_PREFIX: &str = "eth2";
pub const TOPIC_ENCODING_POSTFIX: &str = "ssz";
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";
pub const BEACON_ATTESTATION_TOPIC: &str = "beacon_attestation";
pub const VOLUNTARY_EXIT_TOPIC: &str = "voluntary_exit";
pub const PROPOSER_SLASHING_TOPIC: &str = "proposer_slashing";
pub const ATTESTER_SLASHING_TOPIC: &str = "attester_slashing";
pub const SHARD_TOPIC_PREFIX: &str = "shard";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
/// Network configuration for lighthouse.
pub struct Config {
    /// Data directory where node's keyfile is stored
    pub network_dir: PathBuf,

    /// IP address to listen on.
    pub listen_address: std::net::IpAddr,

    /// The TCP port that libp2p listens on.
    pub libp2p_port: u16,

    /// The address to broadcast to peers about which address we are listening on.
    pub discovery_address: std::net::IpAddr,

    /// UDP port that discovery listens on.
    pub discovery_port: u16,

    /// Target number of connected peers.
    pub max_peers: usize,

    /// A secp256k1 secret key, as bytes in ASCII-encoded hex.
    ///
    /// With or without `0x` prefix.
    #[serde(skip)]
    pub secret_key_hex: Option<String>,

    /// Gossipsub configuration parameters.
    #[serde(skip)]
    pub gs_config: GossipsubConfig,

    /// List of nodes to initially connect to.
    pub boot_nodes: Vec<Enr>,

    /// List of libp2p nodes to initially connect to.
    pub libp2p_nodes: Vec<Multiaddr>,

    /// Client version
    pub client_version: String,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<String>,
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        let mut network_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        network_dir.push(".lighthouse");
        network_dir.push("network");
        Config {
            network_dir,
            listen_address: "127.0.0.1".parse().expect("valid ip address"),
            libp2p_port: 9000,
            discovery_address: "127.0.0.1".parse().expect("valid ip address"),
            discovery_port: 9000,
            max_peers: 10,
            secret_key_hex: None,
            // Note: The topics by default are sent as plain strings. Hashes are an optional
            // parameter.
            gs_config: GossipsubConfigBuilder::new()
                .max_transmit_size(1_048_576)
                .heartbeat_interval(Duration::from_secs(20)) // TODO: Reduce for mainnet
                .propagate_messages(false) // require validation before propagation
                .build(),
            boot_nodes: vec![],
            libp2p_nodes: vec![],
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
        // If a `datadir` has been specified, set the network dir to be inside it.
        if let Some(dir) = args.value_of("datadir") {
            self.network_dir = PathBuf::from(dir).join("network");
        };

        // If a network dir has been specified, override the `datadir` definition.
        if let Some(dir) = args.value_of("network-dir") {
            self.network_dir = PathBuf::from(dir);
        };

        if let Some(listen_address_str) = args.value_of("listen-address") {
            let listen_address = listen_address_str
                .parse()
                .map_err(|_| format!("Invalid listen address: {:?}", listen_address_str))?;
            self.listen_address = listen_address;
            self.discovery_address = listen_address;
        }

        if let Some(max_peers_str) = args.value_of("maxpeers") {
            self.max_peers = max_peers_str
                .parse::<usize>()
                .map_err(|_| format!("Invalid number of max peers: {}", max_peers_str))?;
        }

        if let Some(port_str) = args.value_of("port") {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", port_str))?;
            self.libp2p_port = port;
            self.discovery_port = port;
        }

        if let Some(boot_enr_str) = args.value_of("boot-nodes") {
            self.boot_nodes = boot_enr_str
                .split(',')
                .map(|enr| enr.parse().map_err(|_| format!("Invalid ENR: {}", enr)))
                .collect::<Result<Vec<Enr>, _>>()?;
        }

        if let Some(libp2p_addresses_str) = args.value_of("libp2p-addresses") {
            self.libp2p_nodes = libp2p_addresses_str
                .split(',')
                .map(|multiaddr| {
                    multiaddr
                        .parse()
                        .map_err(|_| format!("Invalid Multiaddr: {}", multiaddr))
                })
                .collect::<Result<Vec<Multiaddr>, _>>()?;
        }

        if let Some(topics_str) = args.value_of("topics") {
            self.topics = topics_str.split(',').map(|s| s.into()).collect();
        }

        if let Some(discovery_address_str) = args.value_of("discovery-address") {
            self.discovery_address = discovery_address_str
                .parse()
                .map_err(|_| format!("Invalid discovery address: {:?}", discovery_address_str))?
        }

        if let Some(disc_port_str) = args.value_of("disc-port") {
            self.discovery_port = disc_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", disc_port_str))?;
        }

        if let Some(p2p_priv_key) = args.value_of("p2p-priv-key") {
            self.secret_key_hex = Some(p2p_priv_key.to_string());
        }

        Ok(())
    }
}
