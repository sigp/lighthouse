//! Simple logic for spawning a Lighthouse BootNode.

use clap::Arg;
use clap_utils::{flags::*, DefaultConfigApp as App};
use std::collections::HashMap;

// TODO: Add DOS prevention CLI params
pub fn cli_app<'a>(file_args: Option<&'a HashMap<&'a str, &'a str>>) -> Result<App<'a>, String> {
    if let Some(args) = file_args {
        for key in args.keys() {
            if !GLOBAL_FLAGS.contains(key)
                && !BOOT_NODE_FLAGS.contains(key)
                && !BEACON_BOOT_NODE_FLAGS.contains(key)
            {
                return Err(format!("--{} is not a valid boot node flag.", key));
            }
        }
    }

    Ok(App::new("boot_node", file_args)
        .about("Start a special Lighthouse process that only serves as a discv5 boot-node. This \
        process will *not* import blocks or perform most typical beacon node functions. Instead, it \
        will simply run the discv5 service and assist nodes on the network to discover each other. \
        This is the recommended way to provide a network boot-node since it has a reduced attack \
        surface compared to a full beacon node.")
        .arg(
            Arg::new(ENR_ADDRESS_FLAG)
                .long(ENR_ADDRESS_FLAG)
                .value_name("IP-ADDRESS")
                .help("The external IP address/ DNS address to broadcast to other peers on how to reach this node. \
                If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
                does not auto-update based on PONG responses in discovery.")
                .required(true)
                .takes_value(true)
                .conflicts_with("network-dir")
        )
        .arg(
            Arg::new(PORT_FLAG)
                .long(PORT_FLAG)
                .value_name("PORT")
                .help("The UDP port to listen on.")
                .default_value("9000")
                .takes_value(true)
        )
        .arg(
            Arg::new(LISTEN_ADDRESS_FLAG)
                .long(LISTEN_ADDRESS_FLAG)
                .value_name("ADDRESS")
                .help("The address the bootnode will listen for UDP connections.")
                .default_value("0.0.0.0")
                .takes_value(true)
        )
        .arg(
            Arg::new(BOOT_NODES_FLAG)
                .long(BOOT_NODES_FLAG)
                .allow_hyphen_values(true)
                .value_name("ENR-LIST/Multiaddr")
                .help("One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to initially add to the local routing table")
                .takes_value(true),
        )
        .arg(
            Arg::new(ENR_UDP_PORT_FLAG)
                .long(ENR_UDP_PORT_FLAG)
                .value_name("PORT")
                .help("The UDP port of the boot node's ENR. This is the port that external peers will dial to reach this boot node. Set this only if the external port differs from the listening port.")
                .takes_value(true)
                .conflicts_with("network-dir")
        )
        .arg(
            Arg::new(ENABLE_ENR_AUTO_UPDATE_FLAG)
                .short('x')
                .long(ENABLE_ENR_AUTO_UPDATE_FLAG)
                .help("Discovery can automatically update the node's local ENR with an external IP address and port as seen by other peers on the network. \
                This enables this feature.")
        )
        .arg(
            Arg::new(DISABLE_PACKET_FILTER_FLAG)
                .long(DISABLE_PACKET_FILTER_FLAG)
                .help("Disables discv5 packet filter. Useful for testing in smaller networks")
        )
        .arg(
            Arg::new(NETWORK_DIR_FLAG)
            .value_name(NETWORK_DIR_FLAG)
                .long("network-dir")
                .help("The directory which contains the enr and it's assoicated private key")
                .takes_value(true)
        ))
}
