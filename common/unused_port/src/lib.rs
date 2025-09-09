use lru_cache::LRUTimeCache;
use parking_lot::Mutex;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::LazyLock;
use std::time::Duration;

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

pub const CACHED_PORTS_TTL: Duration = Duration::from_secs(300);

static FOUND_PORTS_CACHE: LazyLock<Mutex<LRUTimeCache<u16>>> =
    LazyLock::new(|| Mutex::new(LRUTimeCache::new(CACHED_PORTS_TTL)));

/// A convenience wrapper over [`zero_port`].
#[deprecated(note = "Use bind_tcp4_any() which returns a bound socket to avoid TOCTOU")]
pub fn unused_tcp4_port() -> Result<u16, String> {
    zero_port(Transport::Tcp, IpVersion::Ipv4)
}

/// A convenience wrapper over [`zero_port`].
#[deprecated(note = "Use bind_udp4_any() which returns a bound socket to avoid TOCTOU")]
pub fn unused_udp4_port() -> Result<u16, String> {
    zero_port(Transport::Udp, IpVersion::Ipv4)
}

/// A convenience wrapper over [`zero_port`].
#[deprecated(note = "Use bind_tcp6_any() which returns a bound socket to avoid TOCTOU")]
pub fn unused_tcp6_port() -> Result<u16, String> {
    zero_port(Transport::Tcp, IpVersion::Ipv6)
}

/// A convenience wrapper over [`zero_port`].
#[deprecated(note = "Use bind_udp6_any() which returns a bound socket to avoid TOCTOU")]
pub fn unused_udp6_port() -> Result<u16, String> {
    zero_port(Transport::Udp, IpVersion::Ipv6)
}

/// Bind a TCPv4 listener on localhost with an ephemeral port (port 0) and return it.
/// Safe against TOCTOU: the socket remains open and reserved by the OS.
pub fn bind_tcp4_any() -> Result<TcpListener, String> {
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0);
    TcpListener::bind(addr).map_err(|e| format!("Failed to bind TCPv4 listener: {:?}", e))
}

/// Bind a TCPv6 listener on localhost with an ephemeral port (port 0) and return it.
/// Safe against TOCTOU: the socket remains open and reserved by the OS.
pub fn bind_tcp6_any() -> Result<TcpListener, String> {
    let addr = std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0);
    TcpListener::bind(addr).map_err(|e| format!("Failed to bind TCPv6 listener: {:?}", e))
}

/// Bind a UDPv4 socket on localhost with an ephemeral port (port 0) and return it.
/// Safe against TOCTOU: the socket remains open and reserved by the OS.
pub fn bind_udp4_any() -> Result<UdpSocket, String> {
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0);
    UdpSocket::bind(addr).map_err(|e| format!("Failed to bind UDPv4 socket: {:?}", e))
}

/// Bind a UDPv6 socket on localhost with an ephemeral port (port 0) and return it.
/// Safe against TOCTOU: the socket remains open and reserved by the OS.
pub fn bind_udp6_any() -> Result<UdpSocket, String> {
    let addr = std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0);
    UdpSocket::bind(addr).map_err(|e| format!("Failed to bind UDPv6 socket: {:?}", e))
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
#[deprecated(note = "Use bind_*_any() functions that return a bound socket to avoid TOCTOU")]
pub fn zero_port(transport: Transport, ipv: IpVersion) -> Result<u16, String> {
    let localhost = match ipv {
        IpVersion::Ipv4 => std::net::Ipv4Addr::LOCALHOST.into(),
        IpVersion::Ipv6 => std::net::Ipv6Addr::LOCALHOST.into(),
    };
    let socket_addr = std::net::SocketAddr::new(localhost, 0);
    let mut unused_port: u16;
    loop {
        unused_port = find_unused_port(transport, socket_addr)?;
        let mut cache_lock = FOUND_PORTS_CACHE.lock();
        if !cache_lock.contains(&unused_port) {
            cache_lock.insert(unused_port);
            break;
        }
    }

    Ok(unused_port)
}

fn find_unused_port(transport: Transport, socket_addr: SocketAddr) -> Result<u16, String> {
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
