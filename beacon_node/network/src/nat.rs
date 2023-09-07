//! This houses various NAT hole punching strategies.
//!
//! Currently supported strategies:
//! - UPnP

use crate::{NetworkConfig, NetworkMessage};
use if_addrs::get_if_addrs;
use slog::{debug, info};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use tokio::sync::mpsc;
use types::EthSpec;

/// Configuration required to construct the UPnP port mappings.
pub struct UPnPConfig {
    /// The local TCP port.
    tcp_port: u16,
    /// The local UDP discovery port.
    disc_port: u16,
    /// The local UDP quic port.
    quic_port: u16,
    /// Whether discovery is enabled or not.
    disable_discovery: bool,
    /// Whether quic is enabled or not.
    disable_quic_support: bool,
}

/// Contains mappings that managed to be established.
#[derive(Default, Debug)]
pub struct EstablishedUPnPMappings {
    /// A TCP port mapping for libp2p.
    pub tcp_port: Option<u16>,
    /// A UDP port for the QUIC libp2p transport.
    pub udp_quic_port: Option<u16>,
    /// A UDP port for discv5.
    pub udp_disc_port: Option<u16>,
}

impl EstablishedUPnPMappings {
    /// Returns true if at least one value is set.
    pub fn is_some(&self) -> bool {
        self.tcp_port.is_some() || self.udp_quic_port.is_some() || self.udp_disc_port.is_some()
    }

    // Iterator over the UDP ports
    pub fn udp_ports(&self) -> impl Iterator<Item = &u16> {
        self.udp_quic_port.iter().chain(self.udp_disc_port.iter())
    }
}

impl UPnPConfig {
    pub fn from_config(config: &NetworkConfig) -> Option<Self> {
        config.listen_addrs().v4().map(|v4_addr| UPnPConfig {
            tcp_port: v4_addr.tcp_port,
            disc_port: v4_addr.disc_port,
            quic_port: v4_addr.quic_port,
            disable_discovery: config.disable_discovery,
            disable_quic_support: config.disable_quic_support,
        })
    }
}

/// Attempts to construct external port mappings with UPnP.
pub fn construct_upnp_mappings<T: EthSpec>(
    config: UPnPConfig,
    network_send: mpsc::UnboundedSender<NetworkMessage<T>>,
    log: slog::Logger,
) {
    info!(log, "UPnP Attempting to initialise routes");
    match igd::search_gateway(Default::default()) {
        Err(e) => info!(log, "UPnP not available"; "error" => %e),
        Ok(gateway) => {
            // Need to find the local listening address matched with the router subnet
            let interfaces = match get_if_addrs() {
                Ok(v) => v,
                Err(e) => {
                    info!(log, "UPnP failed to get local interfaces"; "error" => %e);
                    return;
                }
            };
            let local_ip = interfaces.iter().find_map(|interface| {
                // Just use the first IP of the first interface that is not a loopback and not an
                // ipv6 address.
                if !interface.is_loopback() {
                    interface.ip().is_ipv4().then(|| interface.ip())
                } else {
                    None
                }
            });

            let local_ip = match local_ip {
                None => {
                    info!(log, "UPnP failed to find local IP address");
                    return;
                }
                Some(v) => v,
            };

            debug!(log, "UPnP Local IP Discovered"; "ip" => ?local_ip);

            let mut mappings = EstablishedUPnPMappings::default();

            match local_ip {
                IpAddr::V4(address) => {
                    let libp2p_socket = SocketAddrV4::new(address, config.tcp_port);
                    let external_ip = gateway.get_external_ip();
                    // We add specific port mappings rather than getting the router to arbitrary assign
                    // one.
                    // I've found this to be more reliable. If multiple users are behind a single
                    // router, they should ideally try to set different port numbers.
                    mappings.tcp_port = add_port_mapping(
                        &gateway,
                        igd::PortMappingProtocol::TCP,
                        libp2p_socket,
                        "tcp",
                        &log,
                    ).map(|_| {
                        let external_socket = external_ip.as_ref().map(|ip| SocketAddr::new((*ip).into(), config.tcp_port)).map_err(|_| ());
                        info!(log, "UPnP TCP route established"; "external_socket" => format!("{}:{}", external_socket.as_ref().map(|ip| ip.to_string()).unwrap_or_else(|_| "".into()), config.tcp_port));
                        config.tcp_port
                    }).ok();

                    let set_udp_mapping = |udp_port| {
                        let udp_socket = SocketAddrV4::new(address, udp_port);
                        add_port_mapping(
                            &gateway,
                            igd::PortMappingProtocol::UDP,
                            udp_socket,
                            "udp",
                            &log,
                        ).map(|_| {
                            info!(log, "UPnP UDP route established"; "external_socket" => format!("{}:{}", external_ip.as_ref().map(|ip| ip.to_string()).unwrap_or_else(|_| "".into()), udp_port));
                        })
                    };

                    // Set the discovery UDP port mapping
                    if !config.disable_discovery && set_udp_mapping(config.disc_port).is_ok() {
                        mappings.udp_disc_port = Some(config.disc_port);
                    }

                    // Set the quic UDP port mapping
                    if !config.disable_quic_support && set_udp_mapping(config.quic_port).is_ok() {
                        mappings.udp_quic_port = Some(config.quic_port);
                    }

                    // report any updates to the network service.
                    if mappings.is_some() {
                        network_send.send(NetworkMessage::UPnPMappingEstablished{ mappings })
                .unwrap_or_else(|e| debug!(log, "Could not send message to the network service"; "error" => %e));
                    }
                }
                _ => debug!(log, "UPnP no routes constructed. IPv6 not supported"),
            }
        }
    };
}

/// Sets up a port mapping for a protocol returning the mapped port if successful.
fn add_port_mapping(
    gateway: &igd::Gateway,
    protocol: igd::PortMappingProtocol,
    socket: SocketAddrV4,
    protocol_string: &'static str,
    log: &slog::Logger,
) -> Result<(), ()> {
    // We add specific port mappings rather than getting the router to arbitrary assign
    // one.
    // I've found this to be more reliable. If multiple users are behind a single
    // router, they should ideally try to set different port numbers.
    let mapping_string = &format!("lighthouse-{}", protocol_string);
    for _ in 0..2 {
        match gateway.add_port(protocol, socket.port(), socket, 0, mapping_string) {
            Err(e) => {
                match e {
                    igd::AddPortError::PortInUse => {
                        // Try and remove and re-create
                        debug!(log, "UPnP port in use, attempting to remap"; "protocol" => protocol_string, "port" => socket.port());
                        match gateway.remove_port(protocol, socket.port()) {
                            Ok(()) => {
                                debug!(log, "UPnP Removed port mapping"; "protocol" => protocol_string,  "port" => socket.port())
                            }
                            Err(e) => {
                                debug!(log, "UPnP Port remove failure"; "protocol" => protocol_string, "port" => socket.port(), "error" => %e);
                                return Err(());
                            }
                        }
                    }
                    e => {
                        info!(log, "UPnP TCP route not set"; "error" => %e);
                        return Err(());
                    }
                }
            }
            Ok(_) => {
                return Ok(());
            }
        }
    }
    Err(())
}

/// Removes the specified TCP and UDP port mappings.
pub fn remove_mappings(mappings: &EstablishedUPnPMappings, log: &slog::Logger) {
    if mappings.is_some() {
        debug!(log, "Removing UPnP port mappings");
        match igd::search_gateway(Default::default()) {
            Ok(gateway) => {
                if let Some(tcp_port) = mappings.tcp_port {
                    match gateway.remove_port(igd::PortMappingProtocol::TCP, tcp_port) {
                        Ok(()) => debug!(log, "UPnP Removed TCP port mapping"; "port" => tcp_port),
                        Err(e) => {
                            debug!(log, "UPnP Failed to remove TCP port mapping"; "port" => tcp_port, "error" => %e)
                        }
                    }
                }
                for udp_port in mappings.udp_ports() {
                    match gateway.remove_port(igd::PortMappingProtocol::UDP, *udp_port) {
                        Ok(()) => debug!(log, "UPnP Removed UDP port mapping"; "port" => udp_port),
                        Err(e) => {
                            debug!(log, "UPnP Failed to remove UDP port mapping"; "port" => udp_port, "error" => %e)
                        }
                    }
                }
            }
            Err(e) => debug!(log, "UPnP failed to remove mappings"; "error" => %e),
        }
    }
}
