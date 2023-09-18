use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libp2p::{multiaddr::Protocol, Multiaddr};
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

    #[cfg(test)]
    pub fn unused_v4_ports() -> Self {
        ListenAddress::V4(ListenAddr {
            addr: Ipv4Addr::UNSPECIFIED,
            disc_port: unused_port::unused_udp4_port().unwrap(),
            quic_port: unused_port::unused_udp4_port().unwrap(),
            tcp_port: unused_port::unused_tcp4_port().unwrap(),
        })
    }

    #[cfg(test)]
    pub fn unused_v6_ports() -> Self {
        ListenAddress::V6(ListenAddr {
            addr: Ipv6Addr::UNSPECIFIED,
            disc_port: unused_port::unused_udp6_port().unwrap(),
            quic_port: unused_port::unused_udp6_port().unwrap(),
            tcp_port: unused_port::unused_tcp6_port().unwrap(),
        })
    }
}

impl slog::KV for ListenAddress {
    fn serialize(
        &self,
        _record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        if let Some(v4_addr) = self.v4() {
            serializer.emit_arguments("ip4_address", &format_args!("{}", v4_addr.addr))?;
            serializer.emit_u16("disc4_port", v4_addr.disc_port)?;
            serializer.emit_u16("quic4_port", v4_addr.quic_port)?;
            serializer.emit_u16("tcp4_port", v4_addr.tcp_port)?;
        }
        if let Some(v6_addr) = self.v6() {
            serializer.emit_arguments("ip6_address", &format_args!("{}", v6_addr.addr))?;
            serializer.emit_u16("disc6_port", v6_addr.disc_port)?;
            serializer.emit_u16("quic6_port", v6_addr.quic_port)?;
            serializer.emit_u16("tcp6_port", v6_addr.tcp_port)?;
        }
        slog::Result::Ok(())
    }
}
