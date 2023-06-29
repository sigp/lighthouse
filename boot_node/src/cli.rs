//! Simple logic for spawning a Lighthouse BootNode.

use clap::{App, Arg};

// TODO: Add DOS prevention CLI params
pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("boot_node")
        .about("Start a special Lighthouse process that only serves as a discv5 boot-node. This \
        process will *not* import blocks or perform most typical beacon node functions. Instead, it \
        will simply run the discv5 service and assist nodes on the network to discover each other. \
        This is the recommended way to provide a network boot-node since it has a reduced attack \
        surface compared to a full beacon node.")
        .settings(&[clap::AppSettings::ColoredHelp])
        .arg(
            Arg::with_name("enr-address")
                .long("enr-address")
                .value_name("ADDRESS")
                .help("The IP address/ DNS address to broadcast to other peers on how to reach \
                      this node. If a DNS address is provided, the enr-address is set to the IP \
                      address it resolves to and does not auto-update based on PONG responses in \
                      discovery. Set this only if you are sure other nodes can connect to your \
                      local node on this address. This will update the `ip4` or `ip6` ENR fields \
                      accordingly. To update both, set this flag twice with the different values.")
                .multiple(true)
                .max_values(2)
                .required(true)
                .conflicts_with("network-dir")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The UDP port to listen on.")
                .default_value("9000")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("port6")
                .long("port6")
                .value_name("PORT")
                .help("The UDP port to listen on over IpV6 when listening over both Ipv4 and \
                      Ipv6. Defaults to 9090 when required.")
                .default_value("9090")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen-address")
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
                .multiple(true)
                .max_values(2)
                .default_value("0.0.0.0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("boot-nodes")
                .long("boot-nodes")
                .allow_hyphen_values(true)
                .value_name("ENR-LIST/Multiaddr")
                .help("One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to initially add to the local routing table")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-udp-port")
                .long("enr-port")
                .value_name("PORT")
                .help("The UDP port of the boot node's ENR. This is the port that external peers will dial to reach this boot node. Set this only if the external port differs from the listening port.")
                .takes_value(true)
                .conflicts_with("network-dir")
        )
        .arg(
            Arg::with_name("enr-udp6-port")
                .long("enr-udp6-port")
                .value_name("PORT")
                .help("The UDP6 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IpV6.")
                .conflicts_with("network-dir")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enable-enr-auto-update")
                .short("x")
                .long("enable-enr-auto-update")
                .help("Discovery can automatically update the node's local ENR with an external IP address and port as seen by other peers on the network. \
                This enables this feature.")
        )
        .arg(
            Arg::with_name("disable-packet-filter")
                .long("disable-packet-filter")
                .help("Disables discv5 packet filter. Useful for testing in smaller networks")
        )
        .arg(
            Arg::with_name("network-dir")
            .value_name("NETWORK_DIR")
                .long("network-dir")
                .help("The directory which contains the enr and it's associated private key")
                .takes_value(true)
        )
}
