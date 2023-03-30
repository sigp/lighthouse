use std::net::{TcpListener, UdpSocket};

#[derive(Copy, Clone)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Copy, Clone)]
pub enum IpVersion {
    Ipv4,
    Ipv6,
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_tcp4_port() -> Result<u16, String> {
    zero_port(Transport::Tcp, IpVersion::Ipv4)
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_udp4_port() -> Result<u16, String> {
    zero_port(Transport::Udp, IpVersion::Ipv4)
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_tcp6_port() -> Result<u16, String> {
    zero_port(Transport::Tcp, IpVersion::Ipv6)
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_udp6_port() -> Result<u16, String> {
    zero_port(Transport::Udp, IpVersion::Ipv6)
}

/// A bit of hack to find an unused port.
///
/// Does not guarantee that the given port is unused after the function exits, just that it was
/// unused before the function started (i.e., it does not reserve a port).
///
/// ## Notes
///
/// It is possible that users are unable to bind to the ports returned by this function as the OS
/// has a buffer period where it doesn't allow binding to the same port even after the socket is
/// closed. We might have to use SO_REUSEADDR socket option from `std::net2` crate in that case.
pub fn zero_port(transport: Transport, ipv: IpVersion) -> Result<u16, String> {
    let localhost = match ipv {
        IpVersion::Ipv4 => std::net::Ipv4Addr::LOCALHOST.into(),
        IpVersion::Ipv6 => std::net::Ipv6Addr::LOCALHOST.into(),
    };
    let socket_addr = std::net::SocketAddr::new(localhost, 0);
    let local_addr = match transport {
        Transport::Tcp => {
            let listener = TcpListener::bind(socket_addr).map_err(|e| {
                format!("Failed to create TCP listener to find unused port: {:?}", e)
            })?;
            listener.local_addr().map_err(|e| {
                format!(
                    "Failed to read TCP listener local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
        Transport::Udp => {
            let socket = UdpSocket::bind(socket_addr)
                .map_err(|e| format!("Failed to create UDP socket to find unused port: {:?}", e))?;
            socket.local_addr().map_err(|e| {
                format!(
                    "Failed to read UDP socket local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
    };

    Ok(local_addr.port())
}
