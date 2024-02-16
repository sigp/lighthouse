//! Simple logic for spawning a Lighthouse BootNode.

use beacon_node::NetworkConfigurable;
use clap::builder::styling::AnsiColor;
use clap::builder::Styles;
pub use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[command(styles=STYLES)]
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
        value_name = "ADDRESS",
        value_delimiter = ' ',
        num_args = 0..=2,
        required_unless_present = "network-dir",
        conflicts_with = "network-dir",
        help = "The external IP address/DNS address to broadcast to other peers on how to reach this node. \
                If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
                does not auto-update based on PONG responses in discovery.",
    )]
    pub enr_addresses: Option<Vec<String>>,

    #[clap(
        long,
        value_name = "PORT",
        default_value_t = 9000,
        help = "The UDP port to listen on."
    )]
    pub port: u16,

    #[clap(
        long,
        value_name = "PORT",
        default_value_t = 9090,
        help = "The UDP port to listen on over IpV6 when listening over both Ipv4 and \
                Ipv6. Defaults to 9090 when required.."
    )]
    pub port6: u16,

    #[clap(
        long = "listen-address",
        value_name = "ADDRESS",
        default_value = "0.0.0.0",
        value_delimiter = ' ',
        num_args = 0..=2,
        help = "The address the bootnode will listen for UDP communications. To listen \
                over IpV4 and IpV6 set this flag twice with the different values.\n\
                Examples:\n\
                - --listen-address '0.0.0.0' will listen over Ipv4.\n\
                - --listen-address '::' will listen over Ipv6.\n\
                - --listen-address '0.0.0.0' --listen-address '::' will listen over both \
                - --listen-address '0.0.0.0' '::' will also listen over both \
                Ipv4 and Ipv6. The order of the given addresses is not relevant. However, \
                multiple Ipv4, or multiple Ipv6 addresses will not be accepted.",
    )]
    pub listen_addresses: Vec<String>,

    #[clap(
        long,
        value_name = "ENR-LIST/Multiaddr",
        allow_hyphen_values = true,
        value_delimiter = ',',
        help = "One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to \
            initially add to the local routing table"
    )]
    pub boot_nodes: Option<Vec<String>>,

    #[clap(
        long,
        value_name = "PORT",
        conflicts_with = "network-dir",
        help = "The UDP port of the boot node's ENR. This is the port that external peers will dial \
            to reach this boot node. Set this only if the external port differs from the listening port."
    )]
    pub enr_port: Option<u16>,

    #[clap(
        long,
        value_name = "PORT",
        conflicts_with = "network-dir",
        help = "The UDP6 port of the local ENR. Set this only if you are sure other nodes \
                can connect to your local node on this port over IpV6."
    )]
    pub enr_udp6_port: Option<u16>,

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
        long,
        value_name = "NETWORK_DIR",
        help = "The directory which contains the enr and it's assoicated private key",
        conflicts_with_all = &["enr-address","enr-port"],
    )]
    pub network_dir: Option<PathBuf>,
}

impl NetworkConfigurable for BootNode {
    fn get_network_dir(&self) -> Option<PathBuf> {
        self.network_dir.clone()
    }
    fn get_port(&self) -> u16 {
        self.port
    }
    fn get_boot_nodes(&self) -> Option<Vec<String>> {
        self.boot_nodes.clone()
    }
    fn get_enr_udp_port(&self) -> Option<NonZeroU16> {
        todo!()
    }
    fn get_enr_addresses(&self) -> Option<Vec<String>> {
        self.enr_addresses.clone()
    }
    fn is_disable_packet_filter(&self) -> bool {
        self.disable_packet_filter
    }
    fn is_zero_ports(&self) -> bool {
        false
    }
    fn get_listen_addresses(&self) -> Vec<IpAddr> {
        self.listen_addresses
            .iter()
            .map(|addr| addr.parse().unwrap())
            .collect()
    }
    fn get_port6(&self) -> u16 {
        todo!()
    }
    fn get_disc_port(&self) -> Option<u16> {
        todo!()
    }
    fn get_disc6_port(&self) -> Option<u16> {
        todo!()
    }
    fn get_quic_port(&self) -> Option<u16> {
        todo!()
    }
    fn get_quic6_port(&self) -> Option<u16> {
        todo!()
    }
}

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default());
