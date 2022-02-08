use beacon_node::cli::NetworkConfigurable;
pub use clap::{IntoApp, Parser};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "boot_node",
    about = "Start a special Lighthouse process that only serves as a discv5 boot-node. This \
        process will *not* import blocks or perform most typical beacon node functions. Instead, it \
        will simply run the discv5 service and assist nodes on the network to discover each other. \
        This is the recommended way to provide a network boot-node since it has a reduced attack \
        surface compared to a full beacon node."
)]
pub struct BootNode {
    #[clap(
        long,
        value_name = "IP-ADDRESS",
        help = "The external IP address/ DNS address to broadcast to other peers on how to reach this node. \
            If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
             does not auto-update based on PONG responses in discovery.",
        conflicts_with = "network_dir"
    )]
    pub enr_address: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port to listen on.",
        default_value = "9000"
    )]
    pub port: u16,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "The address the bootnode will listen for UDP connections.",
        default_value = "0.0.0.0"
    )]
    pub listen_address: IpAddr,
    #[clap(
        long,
        allow_hyphen_values = true,
        value_name = "ENR-LIST/Multiaddr",
        help = "One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to \
            initially add to the local routing table"
    )]
    pub boot_nodes: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port of the boot node's ENR. This is the port that external peers will dial \
            to reach this boot node. Set this only if the external port differs from the listening port.",
        conflicts_with = "network_dir"
    )]
    pub enr_udp_port: Option<u16>,
    #[clap(
        short = 'x',
        long,
        help = "Discovery can automatically update the node's local ENR with an external IP address \
            and port as seen by other peers on the network. , This enables this feature."
    )]
    pub enable_enr_auto_update: bool,
    #[clap(
        long,
        help = "Disables discv5 packet filter. Useful for testing in smaller networks"
    )]
    pub disable_packet_filter: bool,
    #[clap(
        value_name = "NETWORK_DIR",
        long,
        help = "The directory which contains the enr and it's assoicated private key"
    )]
    pub network_dir: Option<PathBuf>,
}

impl NetworkConfigurable for BootNode {
    fn get_network_dir(&self) -> Option<PathBuf> {
        self.network_dir.clone()
    }
    fn get_listen_address(&self) -> IpAddr {
        self.listen_address
    }
    fn get_port(&self) -> u16 {
        self.port
    }
    fn get_boot_nodes(&self) -> Option<String> {
        self.boot_nodes.clone()
    }
    fn get_enr_udp_port(&self) -> Option<u16> {
        self.enr_udp_port
    }
    fn get_enr_address(&self) -> Option<String> {
        self.enr_address.clone()
    }
    fn is_disable_packet_filter(&self) -> bool {
        self.disable_packet_filter
    }
}
