use beacon_node::{get_data_dir, set_network_config};
use clap::ArgMatches;
use discv5::{enr::CombinedKey, Enr};
use eth2_libp2p::{
    discovery::{create_enr_builder_from_config, use_or_load_enr},
    load_private_key, CombinedKeyExt, NetworkConfig,
};
use std::convert::TryFrom;
use std::net::SocketAddr;

/// A set of configuration parameters for the bootnode, established from CLI arguments.
pub struct BootNodeConfig {
    pub listen_socket: SocketAddr,
    // TODO: Generalise to multiaddr
    pub boot_nodes: Vec<Enr>,
    pub local_enr: Enr,
    pub local_key: CombinedKey,
    pub auto_update: bool,
}

impl TryFrom<&ArgMatches<'_>> for BootNodeConfig {
    type Error = String;

    fn try_from(matches: &ArgMatches<'_>) -> Result<Self, Self::Error> {
        let data_dir = get_data_dir(matches);

        let mut network_config = NetworkConfig::default();

        let logger = slog_scope::logger();

        set_network_config(&mut network_config, matches, &data_dir, &logger, true)?;

        let private_key = load_private_key(&network_config, &logger);
        let local_key = CombinedKey::from_libp2p(&private_key)?;

        let mut local_enr = create_enr_builder_from_config(&network_config)
            .build(&local_key)
            .map_err(|e| format!("Failed to build ENR: {:?}", e))?;

        use_or_load_enr(&local_key, &mut local_enr, &network_config, &logger)?;

        let boot_nodes = {
            if let Some(boot_nodes) = matches.value_of("boot-nodes") {
                boot_nodes
                    .split(',')
                    .map(|enr| enr.parse().map_err(|_| format!("Invalid ENR: {}", enr)))
                    .collect::<Result<Vec<Enr>, _>>()?
            } else {
                Vec::new()
            }
        };

        let auto_update = matches.is_present("enable-enr_auto_update");

        // the address to listen on
        let listen_socket =
            SocketAddr::new(network_config.listen_address, network_config.discovery_port);

        Ok(BootNodeConfig {
            listen_socket,
            boot_nodes,
            local_enr,
            local_key,
            auto_update,
        })
    }
}
