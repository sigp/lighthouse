//! Simple logic for spawning a Lighthouse BootNode.

use clap::{Arg, ArgAction, Command};
use clap_utils::get_color_style;

// TODO: Add DOS prevention CLI params
pub fn cli_app() -> Command {
    Command::new("boot_node")
        .about("Start a special Lighthouse process that only serves as a discv5 boot-node. This \
        process will *not* import blocks or perform most typical beacon node functions. Instead, it \
        will simply run the discv5 service and assist nodes on the network to discover each other. \
        This is the recommended way to provide a network boot-node since it has a reduced attack \
        surface compared to a full beacon node.")
        .styles(get_color_style())
        .arg(
            Arg::new("enr-address")
                .long("enr-address")
                .value_name("ADDRESS")
                .help("The IP address/ DNS address to broadcast to other peers on how to reach \
                      this node. If a DNS address is provided, the enr-address is set to the IP \
                      address it resolves to and does not auto-update based on PONG responses in \
                      discovery. Set this only if you are sure other nodes can connect to your \
                      local node on this address. This will update the `ip4` or `ip6` ENR fields \
                      accordingly. To update both, set this flag twice with the different values.")
                .action(ArgAction::Append)
                .num_args(0..=2)
                .required(true)
                .conflicts_with("network-dir")
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .help("The UDP port to listen on.")
                .default_value("9000")
                .action(ArgAction::Set)
        )
        .arg(
            Arg::new("port6")
                .long("port6")
                .value_name("PORT")
                .help("The UDP port to listen on over IpV6 when listening over both Ipv4 and \
                      Ipv6. Defaults to 9090 when required.")
                .default_value("9090")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address the bootnode will listen for UDP communications. To listen \
                      over IpV4 and IpV6 set this flag twice with the different values.\n\
                      Examples:\n\
                      - --listen-address '0.0.0.0' will listen over Ipv4.\n\
                      - --listen-address '::' will listen over Ipv6.\n\
                      - --listen-address '0.0.0.0' --listen-address '::' will listen over both \
                      Ipv4 and Ipv6. The order of the given addresses is not relevant. However, \
                      multiple Ipv4, or multiple Ipv6 addresses will not be accepted.")
                .num_args(0..=2)
                .default_value("0.0.0.0")
                .action(ArgAction::Append)
        )
        .arg(
            Arg::new("boot-nodes")
                .long("boot-nodes")
                .allow_hyphen_values(true)
                .value_name("ENR-LIST/Multiaddr")
                .help("One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to initially add to the local routing table")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("enr-udp-port")
                .long("enr-port")
                .value_name("PORT")
                .help("The UDP port of the boot node's ENR. This is the port that external peers will dial to reach this boot node. Set this only if the external port differs from the listening port.")
                .action(ArgAction::Set)
                .conflicts_with("network-dir")
        )
        .arg(
            Arg::new("enr-udp6-port")
                .long("enr-udp6-port")
                .value_name("PORT")
                .help("The UDP6 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IpV6.")
                .conflicts_with("network-dir")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("enable-enr-auto-update")
                .short('x')
                .action(ArgAction::SetTrue)
                .long("enable-enr-auto-update")
                .help("Discovery can automatically update the node's local ENR with an external IP address and port as seen by other peers on the network. \
                This enables this feature.")
        )
        .arg(
            Arg::new("disable-packet-filter")
                .action(ArgAction::SetTrue)
                .long("disable-packet-filter")
                .help("Disables discv5 packet filter. Useful for testing in smaller networks")
        )
        .arg(
            Arg::new("network-dir")
            .value_name("NETWORK_DIR")
                .long("network-dir")
                .help("The directory which contains the enr and it's associated private key")
                .action(ArgAction::Set)
        )
        .arg(
            Arg::new("subscribe-all-subnets")
                .long("subscribe-all-subnets")
                .action(ArgAction::SetTrue)
                .help("Subscribe to all subnets regardless of validator count. \
                       This will also advertise the beacon node as being long-lived subscribed to all subnets.")
        )
        .arg(
            Arg::new("import-all-attestations")
                .long("import-all-attestations")
                .help("Import and aggregate all attestations, regardless of validator subscriptions. \
                       This will only import attestations from already-subscribed subnets, use with \
                       --subscribe-all-subnets to ensure all attestations are received for import.")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("shutdown-after-sync")
                .long("shutdown-after-sync")
                .help("Shutdown beacon node as soon as sync is completed. Backfill sync will \
                       not be performed before shutdown.")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("zero-ports")
                .long("zero-ports")
                .short('z')
                .help("Sets all listening TCP/UDP ports to 0, allowing the OS to choose some \
                       arbitrary free ports.")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("disable-peer-scoring")
                .long("disable-peer-scoring")
                .help("Disables peer scoring in lighthouse. WARNING: This is a dev only flag is only meant to be used in local testing scenarios \
                        Using this flag on a real network may cause your node to become eclipsed and see a different view of the network")
                .action(ArgAction::SetTrue)
                .hide(true)
        )
        .arg(
            Arg::new("enr-match")
                .short('e')
                .long("enr-match")
                .action(ArgAction::SetTrue)
                .help("Sets the local ENR IP address and port to match those set for lighthouse. \
                      Specifically, the IP address will be the value of --listen-address and the \
                      UDP port will be --discovery-port.")
        )
        .arg(
            Arg::new("disable-enr-auto-update")
                .short('x')
                .action(ArgAction::SetTrue)
                .long("disable-enr-auto-update")
                .help("Discovery automatically updates the nodes local ENR with an external IP address and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot.")
        )
        .arg(
            Arg::new("disable-discovery")
                .long("disable-discovery")
                .action(ArgAction::SetTrue)
                .help("Disables the discv5 discovery protocol. The node will not search for new peers or participate in the discovery protocol.")
                .hide(true)
        )
        .arg(
            Arg::new("disable-quic")
                .long("disable-quic")
                .action(ArgAction::SetTrue)
                .help("Disables the quic transport. The node will rely solely on the TCP transport for libp2p connections.")
        )
        .arg(
            Arg::new("disable-upnp")
                .long("disable-upnp")
                .help("Disables UPnP support. Setting this will prevent Lighthouse from attempting to automatically establish external port mappings.")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("private")
                .long("private")
                .help("Prevents sending various client identification information.")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("metrics")
                .long("metrics")
                .help("Enable the Prometheus metrics HTTP server. Disabled by default.")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("enable-private-discovery")
                .long("enable-private-discovery")
                .help("Lighthouse by default does not discover private IP addresses. Set this flag to enable connection attempts to local addresses.")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("light-client-server")
                .long("light-client-server")
                .help("Act as a full node supporting light clients on the p2p network \
                       [experimental]")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("proposer-only")
                .long("proposer-only")
                .help("Sets this beacon node at be a block proposer only node. \
                       This will run the beacon node in a minimal configuration that is sufficient for block publishing only. This flag should be used \
                       for a beacon node being referenced by validator client using the --proposer-node flag. This configuration is for enabling more secure setups.")
                .action(ArgAction::SetTrue)
        )
}
