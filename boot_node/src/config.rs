use beacon_node::{get_data_dir, get_eth2_network_config, set_network_config};
use clap::ArgMatches;
use eth2_libp2p::discv5::{enr::CombinedKey, Enr};
use eth2_libp2p::{
    discovery::{create_enr_builder_from_config, load_enr_from_disk, use_or_load_enr},
    load_private_key, CombinedKeyExt, NetworkConfig,
};
use ssz::Encode;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::{marker::PhantomData, path::PathBuf};
use types::EthSpec;

/// A set of configuration parameters for the bootnode, established from CLI arguments.
pub struct BootNodeConfig<T: EthSpec> {
    pub listen_socket: SocketAddr,
    // TODO: Generalise to multiaddr
    pub boot_nodes: Vec<Enr>,
    pub local_enr: Enr,
    pub local_key: CombinedKey,
    pub auto_update: bool,
    phantom: PhantomData<T>,
}

impl<T: EthSpec> TryFrom<&ArgMatches<'_>> for BootNodeConfig<T> {
    type Error = String;

    fn try_from(matches: &ArgMatches<'_>) -> Result<Self, Self::Error> {
        let data_dir = get_data_dir(matches);

        // Try and grab network config from input CLI params
        let eth2_network_config = get_eth2_network_config(&matches)?;

        // Try and obtain bootnodes

        let boot_nodes = {
            let mut boot_nodes = Vec::new();

            if let Some(enr) = &eth2_network_config.boot_enr {
                boot_nodes.extend_from_slice(enr);
            }

            if let Some(nodes) = matches.value_of("boot-nodes") {
                boot_nodes.extend_from_slice(
                    &nodes
                        .split(',')
                        .map(|enr| enr.parse().map_err(|_| format!("Invalid ENR: {}", enr)))
                        .collect::<Result<Vec<Enr>, _>>()?,
                );
            }

            boot_nodes
        };

        let mut network_config = NetworkConfig::default();

        let logger = slog_scope::logger();

        set_network_config(&mut network_config, matches, &data_dir, &logger, true)?;
        // default to the standard port
        if !matches.is_present("enr-udp-port") {
            network_config.enr_udp_port = Some(
                matches
                    .value_of("port")
                    .expect("Value required")
                    .parse()
                    .map_err(|_| "Invalid port number")?,
            );
        }

        let auto_update = matches.is_present("enable-enr_auto_update");

        // the address to listen on
        let listen_socket =
            SocketAddr::new(network_config.listen_address, network_config.discovery_port);

        let private_key = load_private_key(&network_config, &logger);
        let local_key = CombinedKey::from_libp2p(&private_key)?;

        let local_enr = if let Some(dir) = matches.value_of("network-dir") {
            let network_dir: PathBuf = dir.into();
            load_enr_from_disk(&network_dir)?
        } else {
            // build the enr_fork_id and add it to the local_enr if it exists
            let enr_fork = {
                let spec = eth2_network_config.chain_spec::<T>()?;

                if eth2_network_config.beacon_state_is_known() {
                    let genesis_state = eth2_network_config.beacon_state::<T>()?;

                    slog::info!(logger, "Genesis state found"; "root" => genesis_state.canonical_root().to_string());
                    let enr_fork = spec.enr_fork_id(
                        types::Slot::from(0u64),
                        genesis_state.genesis_validators_root(),
                    );

                    Some(enr_fork.as_ssz_bytes())
                } else {
                    slog::warn!(
                        logger,
                        "No genesis state provided. No Eth2 field added to the ENR"
                    );
                    None
                }
            };

            // Build the local ENR

            let mut local_enr = {
                let mut builder = create_enr_builder_from_config(&network_config, false);

                // If we know of the ENR field, add it to the initial construction
                if let Some(enr_fork_bytes) = enr_fork {
                    builder.add_value("eth2", enr_fork_bytes.as_slice());
                }
                builder
                    .build(&local_key)
                    .map_err(|e| format!("Failed to build ENR: {:?}", e))?
            };

            use_or_load_enr(&local_key, &mut local_enr, &network_config, &logger)?;
            local_enr
        };

        Ok(BootNodeConfig {
            listen_socket,
            boot_nodes,
            local_enr,
            local_key,
            auto_update,
            phantom: PhantomData,
        })
    }
}
