use lru_cache::LRUTimeCache;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
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

/// Binds a TCP socket to an available port on IPv4 and returns the listener.
///
/// This function uses `SO_REUSEADDR` to mitigate the TOCTOU race where another process
/// could claim the port between finding it and the caller binding to it.
pub fn bind_tcp4_any() -> Result<TcpListener, String> {
    bind_tcp(IpVersion::Ipv4)
}

/// Binds a TCP socket to an available port on IPv6 and returns the listener.
pub fn bind_tcp6_any() -> Result<TcpListener, String> {
    bind_tcp(IpVersion::Ipv6)
}

/// Binds a UDP socket to an available port on IPv4 and returns the socket.
pub fn bind_udp4_any() -> Result<UdpSocket, String> {
    bind_udp(IpVersion::Ipv4)
}

/// Binds a UDP socket to an available port on IPv6 and returns the socket.
pub fn bind_udp6_any() -> Result<UdpSocket, String> {
    bind_udp(IpVersion::Ipv6)
}

fn socket2_domain(ipv: IpVersion) -> Domain {
    match ipv {
        IpVersion::Ipv4 => Domain::IPV4,
        IpVersion::Ipv6 => Domain::IPV6,
    }
}

fn bind_tcp(ipv: IpVersion) -> Result<TcpListener, String> {
    let localhost = match ipv {
        IpVersion::Ipv4 => std::net::Ipv4Addr::LOCALHOST.into(),
        IpVersion::Ipv6 => std::net::Ipv6Addr::LOCALHOST.into(),
    };
    let socket_addr = SocketAddr::new(localhost, 0);

    let domain = socket2_domain(ipv);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("Failed to create TCP socket: {}", e))?;
    socket.set_reuse_address(true)
        .map_err(|e| format!("Failed to set SO_REUSEADDR: {}", e))?;
    socket.bind(&socket_addr.into())
        .map_err(|e| format!("Failed to bind TCP socket: {}", e))?;
    socket.listen(1)
        .map_err(|e| format!("Failed to listen on TCP socket: {}", e))?;
    // Use `From::from` to convert socket2::Socket into std::net::TcpListener
    let listener: TcpListener = socket.into();
    Ok(listener)
}

fn bind_udp(ipv: IpVersion) -> Result<UdpSocket, String> {
    let localhost = match ipv {
        IpVersion::Ipv4 => std::net::Ipv4Addr::LOCALHOST.into(),
        IpVersion::Ipv6 => std::net::Ipv6Addr::LOCALHOST.into(),
    };
    let socket_addr = SocketAddr::new(localhost, 0);

    let domain = socket2_domain(ipv);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("Failed to create UDP socket: {}", e))?;
    socket.set_reuse_address(true)
        .map_err(|e| format!("Failed to set SO_REUSEADDR: {}", e))?;
    socket.bind(&socket_addr.into())
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
    let sock: UdpSocket = socket.into();
    Ok(sock)
}

/// Finds an unused port using `SO_REUSEADDR` to reduce the TOCTOU race window.
///
/// Unlike the previous implementation which dropped the socket before returning the port,
/// this function uses `SO_REUSEADDR` so that subsequent binds to the same port are more
/// likely to succeed even if the socket is in TIME_WAIT state.
pub fn zero_port(transport: Transport, ipv: IpVersion) -> Result<u16, String> {
    let port = match transport {
        Transport::Tcp => {
            bind_tcp(ipv)?.local_addr().map(|a| a.port())
        }
        Transport::Udp => {
            bind_udp(ipv)?.local_addr().map(|a| a.port())
        }
    }.map_err(|e| format!("Failed to read local addr: {}", e))?;

    let mut cache_lock = FOUND_PORTS_CACHE.lock();
    if !cache_lock.contains(&port) {
        cache_lock.insert(port);
    }
    Ok(port)
}
