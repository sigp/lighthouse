use std::net::{TcpListener, UdpSocket};

#[derive(Copy, Clone)]
pub enum Transport {
    Tcp,
    Udp,
}

/// A convenience function for `unused_port(Transport::Tcp)`.
pub fn unused_tcp_port() -> Result<u16, String> {
    unused_port(Transport::Tcp)
}

/// A convenience function for `unused_port(Transport::Tcp)`.
pub fn unused_udp_port() -> Result<u16, String> {
    unused_port(Transport::Udp)
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
pub fn unused_port(transport: Transport) -> Result<u16, String> {
    let local_addr = match transport {
        Transport::Tcp => {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| {
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
            let socket = UdpSocket::bind("127.0.0.1:0")
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
