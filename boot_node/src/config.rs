use beacon_node::{get_data_dir, set_network_config};
use bytes::Bytes;
use clap::ArgMatches;
use enr::CombinedKey;
use eth2_network_config::Eth2NetworkConfig;
use lighthouse_network::discv5::{self, Enr};
use lighthouse_network::{
    NetworkConfig,
    discovery::{load_enr_from_disk, use_or_load_enr},
    load_private_key,
};
use network_utils::enr_ext::CombinedKeyExt;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use std::{marker::PhantomData, path::PathBuf};
use tracing::{info, warn};
use types::EthSpec;

/// Unsolicited discovery packets per second that a boot node accepts from all sources together.
const BOOT_NODE_UNSOLICITED_PACKETS_PER_SECOND: u64 = 100;

/// Replaces the beacon node's discovery packet filter limits, which are too low for a boot node.
///
/// A boot node exists to answer unsolicited packets, but the beacon node limit of 10 per second
/// in total drops the excess before any reply. The per-IP and per-node limits do not change.
/// The node-ID-per-IP limit is removed: node IDs do not expire by time, so it bans an IP that
/// many nodes share behind NAT. The per-IP rate limit still bans an IP that sends too much.
fn apply_boot_node_packet_filter(config: &mut discv5::Config) {
    config.filter_rate_limiter = Some(
        discv5::RateLimiterBuilder::new()
            .total_n_every(
                BOOT_NODE_UNSOLICITED_PACKETS_PER_SECOND,
                Duration::from_secs(1),
            )
            .ip_n_every(9, Duration::from_secs(1))
            .node_n_every(8, Duration::from_secs(1))
            .build()
            .expect("The total rate limit has been specified"),
    );
    config.filter_max_nodes_per_ip = None;
}

/// A set of configuration parameters for the bootnode, established from CLI arguments.
pub struct BootNodeConfig<E: EthSpec> {
    // TODO: Generalise to multiaddr
    pub boot_nodes: Vec<Enr>,
    pub local_enr: Enr,
    pub local_key: CombinedKey,
    pub discv5_config: discv5::Config,
    phantom: PhantomData<E>,
}

impl<E: EthSpec> BootNodeConfig<E> {
    pub async fn new(
        matches: &ArgMatches,
        eth2_network_config: &Eth2NetworkConfig,
    ) -> Result<Self, String> {
        let data_dir = get_data_dir(matches);
        // Try and obtain bootnodes

        let boot_nodes = {
            let mut boot_nodes = Vec::new();

            if let Some(enr) = &eth2_network_config.boot_enr {
                boot_nodes.extend_from_slice(enr);
            }

            if let Some(nodes) = matches.get_one::<String>("boot-nodes") {
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

        set_network_config(&mut network_config, matches, &data_dir)?;
        apply_boot_node_packet_filter(&mut network_config.discv5_config);

        // Set the Enr Discovery ports to the listening ports if not present.
        if let Some(listening_addr_v4) = network_config.listen_addrs().v4()
            && network_config.enr_udp4_port.is_none()
        {
            network_config.enr_udp4_port = Some(
                network_config.enr_udp4_port.unwrap_or(
                    listening_addr_v4
                        .disc_port
                        .try_into()
                        .map_err(|_| "boot node enr-udp-port not set and listening port is zero")?,
                ),
            )
        };

        if let Some(listening_addr_v6) = network_config.listen_addrs().v6()
            && network_config.enr_udp6_port.is_none()
        {
            network_config.enr_udp6_port = Some(
                network_config.enr_udp6_port.unwrap_or(
                    listening_addr_v6
                        .disc_port
                        .try_into()
                        .map_err(|_| "boot node enr-udp-port not set and listening port is zero")?,
                ),
            )
        };

        // By default this is enabled. If it is not set, revert to false.
        if !matches.get_flag("enable-enr-auto-update") {
            network_config.discv5_config.enr_update = false;
        }

        let private_key = load_private_key(&network_config);
        let local_key = CombinedKey::from_libp2p(private_key)?;

        let local_enr = if let Some(dir) = matches.get_one::<String>("network-dir") {
            let network_dir: PathBuf = dir.into();
            load_enr_from_disk(&network_dir)?
        } else {
            // build the enr_fork_id and add it to the local_enr if it exists
            let enr_fork = {
                let spec = eth2_network_config.chain_spec::<E>()?;

                let genesis_state_url: Option<String> =
                    clap_utils::parse_optional(matches, "genesis-state-url")?;
                let genesis_state_url_timeout =
                    clap_utils::parse_required(matches, "genesis-state-url-timeout")
                        .map(Duration::from_secs)?;

                if eth2_network_config.genesis_state_is_known() {
                    let mut genesis_state = eth2_network_config
                        .genesis_state::<E>(genesis_state_url.as_deref(), genesis_state_url_timeout).await?
                        .ok_or_else(|| {
                            "The genesis state for this network is not known, this is an unsupported mode"
                                .to_string()
                        })?;

                    let genesis_state_root = genesis_state
                        .canonical_root()
                        .map_err(|e| format!("Error hashing genesis state: {e:?}"))?;
                    info!(root = ?genesis_state_root, "Genesis state found");
                    let enr_fork = spec.enr_fork_id::<E>(
                        types::Slot::from(0u64),
                        genesis_state.genesis_validators_root(),
                    );

                    Some(enr_fork.as_ssz_bytes())
                } else {
                    warn!("No genesis state provided. No Eth2 field added to the ENR");
                    None
                }
            };

            // Build the local ENR

            let mut local_enr = {
                let (maybe_ipv4_address, maybe_ipv6_address) = network_config.enr_address;
                let mut builder = discv5::Enr::builder();

                if let Some(ip) = maybe_ipv4_address {
                    builder.ip4(ip);
                }

                if let Some(ip) = maybe_ipv6_address {
                    builder.ip6(ip);
                }

                if let Some(udp4_port) = network_config.enr_udp4_port {
                    builder.udp4(udp4_port.get());
                }

                if let Some(udp6_port) = network_config.enr_udp6_port {
                    builder.udp6(udp6_port.get());
                }

                // If we know of the ENR field, add it to the initial construction
                if let Some(enr_fork_bytes) = enr_fork {
                    builder.add_value::<Bytes>("eth2", &enr_fork_bytes.into());
                }
                builder
                    .build(&local_key)
                    .map_err(|e| format!("Failed to build ENR: {:?}", e))?
            };

            use_or_load_enr(&local_key, &mut local_enr, &network_config)?;
            local_enr
        };

        Ok(BootNodeConfig {
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
/// Its fields are a subset of the fields of `BootNodeConfig`, some of them are copied from `discv5::Config`.
#[derive(Serialize, Deserialize)]
pub struct BootNodeConfigSerialization {
    pub ipv4_listen_socket: Option<SocketAddrV4>,
    pub ipv6_listen_socket: Option<SocketAddrV6>,
    // TODO: Generalise to multiaddr
    pub boot_nodes: Vec<Enr>,
    pub local_enr: Enr,
    pub disable_packet_filter: bool,
    pub enable_enr_auto_update: bool,
}

impl BootNodeConfigSerialization {
    /// Returns a `BootNodeConfigSerialization` obtained from copying resp. cloning the
    /// relevant fields of `config`
    pub fn from_config_ref<E: EthSpec>(config: &BootNodeConfig<E>) -> Self {
        let BootNodeConfig {
            boot_nodes,
            local_enr,
            local_key: _,
            discv5_config,
            phantom: _,
        } = config;

        let (ipv4_listen_socket, ipv6_listen_socket) = match discv5_config.listen_config {
            lighthouse_network::discv5::ListenConfig::Ipv4 { ip, port } => {
                (Some(SocketAddrV4::new(ip, port)), None)
            }
            lighthouse_network::discv5::ListenConfig::Ipv6 { ip, port } => {
                (None, Some(SocketAddrV6::new(ip, port, 0, 0)))
            }
            lighthouse_network::discv5::ListenConfig::DualStack {
                ipv4,
                ipv4_port,
                ipv6,
                ipv6_port,
            } => (
                Some(SocketAddrV4::new(ipv4, ipv4_port)),
                Some(SocketAddrV6::new(ipv6, ipv6_port, 0, 0)),
            ),
            lighthouse_network::discv5::ListenConfig::FromSockets { ref ipv4, ref ipv6 } => (
                ipv4.as_ref()
                    .and_then(|socket| socket.local_addr().ok())
                    .and_then(|addr| match addr {
                        SocketAddr::V4(addr) => Some(addr),
                        SocketAddr::V6(_) => None,
                    }),
                ipv6.as_ref()
                    .and_then(|socket| socket.local_addr().ok())
                    .and_then(|addr| match addr {
                        SocketAddr::V6(addr) => Some(addr),
                        SocketAddr::V4(_) => None,
                    }),
            ),
        };

        BootNodeConfigSerialization {
            ipv4_listen_socket,
            ipv6_listen_socket,
            boot_nodes: boot_nodes.clone(),
            local_enr: local_enr.clone(),
            disable_packet_filter: !discv5_config.enable_packet_filter,
            enable_enr_auto_update: discv5_config.enr_update,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_node_packet_filter_raises_total_limit_and_allows_shared_ips() {
        let default = NetworkConfig::default().discv5_config;
        let mut config = NetworkConfig::default().discv5_config;
        apply_boot_node_packet_filter(&mut config);

        let total_per_second = |config: &discv5::Config| {
            config
                .filter_rate_limiter
                .as_ref()
                .unwrap()
                .total_requests_per_second()
        };
        assert!(total_per_second(&config) > total_per_second(&default));
        assert_eq!(config.filter_max_nodes_per_ip, None);
        assert_eq!(
            config.filter_max_bans_per_ip,
            default.filter_max_bans_per_ip
        );
    }
}
