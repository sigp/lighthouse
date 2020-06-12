//! Simple logic for spawning a Lighthouse BootNode.

use clap::{App, Arg};

// TODO: Add DOS prevention CLI params
pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("boot_node")
        .about("Start a Lighthouse boot node.")
        .settings(&[clap::AppSettings::ArgsNegateSubcommands, clap::AppSettings::SubcommandsNegateReqs, clap::AppSettings::ColoredHelp])
        .arg(
            Arg::with_name("boot-node-enr-address")
                .value_name("ENR-ADDRESS")
                .help("The external IP address/ DNS address to broadcast to other peers on how to reach this node. \
                If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
                does not auto-update based on PONG responses in discovery.") 
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .value_name("PORT")
                .help("The UDP port to listen on.")
                .default_value("9000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("The verbosity level for emitting logs.")
                .takes_value(true)
                .possible_values(&["info", "debug", "trace", "warn", "error", "crit"])
                .default_value("info"),
        )
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address the bootnode will listen for UDP connections.")
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
            Arg::with_name("enr-port")
                .long("enr-port")
                .value_name("PORT")
                .help("The UDP port of the boot node's ENR. This is the port that external peers will dial to reach this boot node. Set this only if the external port differs from the listening port.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enable-enr-auto-update")
                .short("x")
                .long("enable-enr-auto-update")
                .help("Discovery can automatically update the node's local ENR with an external IP address and port as seen by other peers on the network. \
                This enables this feature.")
                .takes_value(true),
        )
}
