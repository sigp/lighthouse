use beacon_node::{get_data_dir, set_network_config};
use clap::ArgMatches;
use eth2_network_config::Eth2NetworkConfig;
use lighthouse_network::discovery::create_enr_builder_from_config;
use lighthouse_network::discv5::IpMode;
use lighthouse_network::discv5::{enr::CombinedKey, Discv5Config, Enr};
use lighthouse_network::{
    discovery::{load_enr_from_disk, use_or_load_enr},
    load_private_key, CombinedKeyExt, NetworkConfig,
};
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
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
    pub discv5_config: Discv5Config,
    phantom: PhantomData<T>,
}

impl<T: EthSpec> BootNodeConfig<T> {
    pub fn new(
        matches: &ArgMatches<'_>,
        eth2_network_config: &Eth2NetworkConfig,
    ) -> Result<Self, String> {
        let data_dir = get_data_dir(matches);

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

        set_network_config(&mut network_config, matches, &data_dir, &logger)?;

        // Set the Enr UDP ports to the listening ports if not present.
        if let Some(listening_addr_v4) = network_config.listen_addrs().v4() {
            network_config.enr_udp4_port = Some(
                network_config
                    .enr_udp4_port
                    .unwrap_or(listening_addr_v4.udp_port),
            )
        };

        if let Some(listening_addr_v6) = network_config.listen_addrs().v6() {
            network_config.enr_udp6_port = Some(
                network_config
                    .enr_udp6_port
                    .unwrap_or(listening_addr_v6.udp_port),
            )
        };

        // By default this is enabled. If it is not set, revert to false.
        if !matches.is_present("enable-enr-auto-update") {
            network_config.discv5_config.enr_update = false;
        }

        // the address to listen on
        let listen_socket = match network_config.listen_addrs().clone() {
            lighthouse_network::ListenAddress::V4(v4_addr) => {
                // Set explicitly as ipv4 otherwise
                network_config.discv5_config.ip_mode = IpMode::Ip4;
                v4_addr.udp_socket_addr()
            }
            lighthouse_network::ListenAddress::V6(v6_addr) => {
                // create ipv6 sockets and enable ipv4 mapped addresses.
                network_config.discv5_config.ip_mode = IpMode::Ip6 {
                    enable_mapped_addresses: false,
                };

                v6_addr.udp_socket_addr()
            }
            lighthouse_network::ListenAddress::DualStack(_v4_addr, v6_addr) => {
                // create ipv6 sockets and enable ipv4 mapped addresses.
                network_config.discv5_config.ip_mode = IpMode::Ip6 {
                    enable_mapped_addresses: true,
                };

                v6_addr.udp_socket_addr()
            }
        };

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
                    let enr_fork = spec.enr_fork_id::<T>(
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
                let enable_tcp = false;
                let mut builder = create_enr_builder_from_config(&network_config, enable_tcp);
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
            discv5_config: network_config.discv5_config,
            phantom: PhantomData,
        })
    }
}

/// The set of configuration parameters that can safely be (de)serialized.
///
/// Its fields are a subset of the fields of `BootNodeConfig`, some of them are copied from `Discv5Config`.
#[derive(Serialize, Deserialize)]
pub struct BootNodeConfigSerialization {
    pub listen_socket: SocketAddr,
    // TODO: Generalise to multiaddr
    pub boot_nodes: Vec<Enr>,
    pub local_enr: Enr,
    pub disable_packet_filter: bool,
    pub enable_enr_auto_update: bool,
}

impl BootNodeConfigSerialization {
    /// Returns a `BootNodeConfigSerialization` obtained from copying resp. cloning the
    /// relevant fields of `config`
    pub fn from_config_ref<T: EthSpec>(config: &BootNodeConfig<T>) -> Self {
        let BootNodeConfig {
            listen_socket,
            boot_nodes,
            local_enr,
            local_key: _,
            discv5_config,
            phantom: _,
        } = config;

        BootNodeConfigSerialization {
            listen_socket: *listen_socket,
            boot_nodes: boot_nodes.clone(),
            local_enr: local_enr.clone(),
            disable_packet_filter: !discv5_config.enable_packet_filter,
            enable_enr_auto_update: discv5_config.enr_update,
        }
    }
}
