use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use multiaddr::{Multiaddr, Protocol};
use serde::{Deserialize, Serialize};

/// A listening address composed by an Ip, an UDP port and a TCP port.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListenAddr<Ip> {
    /// The IP address we will listen on.
    pub addr: Ip,
    /// The UDP port that discovery will listen on.
    pub disc_port: u16,
    /// The UDP port that QUIC will listen on.
    pub quic_port: u16,
    /// The TCP port that libp2p will listen on.
    pub tcp_port: u16,
}

impl<Ip: Into<IpAddr> + Clone> ListenAddr<Ip> {
    pub fn discovery_socket_addr(&self) -> SocketAddr {
        (self.addr.clone().into(), self.disc_port).into()
    }

    pub fn quic_socket_addr(&self) -> SocketAddr {
        (self.addr.clone().into(), self.quic_port).into()
    }

    pub fn tcp_socket_addr(&self) -> SocketAddr {
        (self.addr.clone().into(), self.tcp_port).into()
    }
}

/// Types of listening addresses Lighthouse can accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ListenAddress {
    V4(ListenAddr<Ipv4Addr>),
    V6(ListenAddr<Ipv6Addr>),
    DualStack(ListenAddr<Ipv4Addr>, ListenAddr<Ipv6Addr>),
}

impl ListenAddress {
    /// Return the listening address over IpV4 if any.
    pub fn v4(&self) -> Option<&ListenAddr<Ipv4Addr>> {
        match self {
            ListenAddress::V4(v4_addr) | ListenAddress::DualStack(v4_addr, _) => Some(v4_addr),
            ListenAddress::V6(_) => None,
        }
    }

    /// Return the listening address over IpV6 if any.
    pub fn v6(&self) -> Option<&ListenAddr<Ipv6Addr>> {
        match self {
            ListenAddress::V6(v6_addr) | ListenAddress::DualStack(_, v6_addr) => Some(v6_addr),
            ListenAddress::V4(_) => None,
        }
    }

    /// Returns the addresses the Swarm will listen on, given the setup.
    pub fn libp2p_addresses(&self) -> impl Iterator<Item = Multiaddr> {
        let v4_tcp_multiaddr = self
            .v4()
            .map(|v4_addr| Multiaddr::from(v4_addr.addr).with(Protocol::Tcp(v4_addr.tcp_port)));

        let v4_quic_multiaddr = self.v4().map(|v4_addr| {
            Multiaddr::from(v4_addr.addr)
                .with(Protocol::Udp(v4_addr.quic_port))
                .with(Protocol::QuicV1)
        });

        let v6_quic_multiaddr = self.v6().map(|v6_addr| {
            Multiaddr::from(v6_addr.addr)
                .with(Protocol::Udp(v6_addr.quic_port))
                .with(Protocol::QuicV1)
        });

        let v6_tcp_multiaddr = self
            .v6()
            .map(|v6_addr| Multiaddr::from(v6_addr.addr).with(Protocol::Tcp(v6_addr.tcp_port)));

        v4_tcp_multiaddr
            .into_iter()
            .chain(v4_quic_multiaddr)
            .chain(v6_quic_multiaddr)
            .chain(v6_tcp_multiaddr)
    }

    // Used for testing
    pub fn zero_v4_ports() -> Self {
        ListenAddress::V4(ListenAddr {
            addr: Ipv4Addr::UNSPECIFIED,
            disc_port: 0,
            quic_port: 0,
            tcp_port: 0,
        })
    }

    pub fn zero_v6_ports() -> Self {
        ListenAddress::V6(ListenAddr {
            addr: Ipv6Addr::UNSPECIFIED,
            disc_port: 0,
            quic_port: 0,
            tcp_port: 0,
        })
    }
}

/// Compute all beacon listening ports (TCP, discovery UDP, QUIC UDP) at once.
/// Returns a tuple of (tcp_port, disc_port, quic_port).
///
/// When `use_zero_ports` is true, all ports are set to 0 (OS assigns ephemeral ports).
/// Otherwise:
/// - TCP port uses the provided `tcp_port`
/// - Discovery port defaults to TCP port (TCP and UDP can share the same port number)
/// - QUIC port defaults to TCP port + 1 (to avoid conflict with discovery UDP)
pub fn compute_listen_ports(
    use_zero_ports: bool,
    tcp_port: u16,
    maybe_disc_port: Option<u16>,
    maybe_quic_port: Option<u16>,
) -> (u16, u16, u16) {
    if use_zero_ports {
        return (0, 0, 0);
    }

    let disc_port = maybe_disc_port.unwrap_or(tcp_port); // udp / tcp can listen to same port

    // Handle QUIC port with overflow safety
    let quic_port = maybe_quic_port.unwrap_or_else(|| {
        if tcp_port == 0 || tcp_port == u16::MAX {
            // If tcp_port is 0 or MAX, set quic_port to 0
            0
        } else {
            tcp_port.wrapping_add(1)
        }
    });

    (tcp_port, disc_port, quic_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_listen_ports_with_zero_ports_flag() {
        // When use_zero_ports is true, all ports should be 0 regardless of input
        assert_eq!(compute_listen_ports(true, 9000, None, None), (0, 0, 0));
    }

    #[test]
    fn test_compute_listen_ports_default_behavior() {
        // Default behavior: disc_port = tcp_port, quic_port = tcp_port + 1
        let (tcp, disc, quic) = compute_listen_ports(false, 9000, None, None);
        assert_eq!(tcp, 9000);
        assert_eq!(disc, 9000); // Discovery defaults to TCP port (UDP and TCP can listen to same port)
        assert_eq!(quic, 9001); // QUIC defaults to TCP port + 1
    }

    #[test]
    fn test_compute_listen_ports_with_explicit_ports() {
        // Explicit discovery port should be used
        let (tcp, disc, quic) = compute_listen_ports(false, 9000, Some(8000),   Some(7000));
        assert_eq!(tcp, 9000);
        assert_eq!(disc, 8000); // Explicit discovery port
        assert_eq!(quic, 7000); // Explicit QUIC port
    }

    #[test]
    fn test_compute_listen_ports_with_zero_tcp_port() {
        // Edge case: tcp_port = 0 without use_zero_ports flag
        // QUIC and discovery ports should also be 0
        assert_eq!(compute_listen_ports(false, 0, None, None), (0, 0, 0));
    }

    #[test]
    fn test_compute_listen_ports_max_port_overflow() {
        // Edge case: tcp_port = u16::MAX (65535)
        // QUIC should be 0 to avoid overflow panic
        let (tcp, disc, quic) = compute_listen_ports(false, u16::MAX, None, None);
        assert_eq!(tcp, u16::MAX);
        assert_eq!(disc, u16::MAX);
        assert_eq!(quic, 0); // u16::MAX would overflow, so we use 0
    }
}
