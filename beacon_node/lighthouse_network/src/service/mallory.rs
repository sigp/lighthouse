use super::*;
use libp2p::core::transport::{ListenerId, TransportError};
use libp2p::core::ConnectedPoint;
use libp2p::swarm::*;
use std::io;
/// Custom error that can be produced by the [`ConnectionHandler`] of the [`NetworkBehaviour`].
#[derive(Debug)]
pub enum MallorySwarmEvent {
    /// One of the listeners gracefully closed.
    ListenerClosed {
        /// The listener that closed.
        listener_id: libp2p::core::transport::ListenerId,
        /// The addresses that the listener was listening on. These addresses are now considered
        /// expired, similar to if a [`ExpiredListenAddr`](SwarmEvent::ExpiredListenAddr) event
        /// has been generated for each of them.
        addresses: Vec<Multiaddr>,
        /// Reason for the closure. Contains `Ok(())` if the stream produced `None`, or `Err`
        /// if the stream produced an error.
        reason: Result<(), std::io::Error>,
    },
    /// One of the listeners reported a non-fatal error.
    ListenerError {
        /// The listener that errored.
        listener_id: ListenerId,
        /// The listener error.
        error: io::Error,
    },
    /// Outgoing connection attempt failed.
    OutgoingConnectionError {
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// If known, [`PeerId`] of the peer we tried to reach.
        peer_id: Option<PeerId>,
        /// Error that has been encountered.
        error: DialError,
    },
    IncomingConnection {
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Local connection address.
        /// This address has been earlier reported with a [`NewListenAddr`](SwarmEvent::NewListenAddr)
        /// event.
        local_addr: Multiaddr,
        /// Address used to send back data to the remote.
        send_back_addr: Multiaddr,
    },
    /// An error happened on a connection during its initial handshake.
    ///
    /// This can include, for example, an error during the handshake of the encryption layer, or
    /// the connection unexpectedly closed.
    IncomingConnectionError {
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Local connection address.
        /// This address has been earlier reported with a [`NewListenAddr`](SwarmEvent::NewListenAddr)
        /// event.
        local_addr: Multiaddr,
        /// Address used to send back data to the remote.
        send_back_addr: Multiaddr,
        /// The error that happened.
        error: ListenError,
    },
    Dialing {
        /// Identity of the peer that we are connecting to.
        peer_id: Option<PeerId>,
        /// Identifier of the connection.
        connection_id: ConnectionId,
    },
    ConnectionClosed {
        /// Identity of the peer that we have connected to.
        peer_id: PeerId,
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Endpoint of the connection that has been closed.
        endpoint: ConnectedPoint,
        /// Number of other remaining connections to this same peer.
        num_established: u32,
        /// Reason for the disconnection, if it was not a successful
        /// active close.
        cause: Option<String>,
    },
    /// A connection to the given peer has been opened.
    ConnectionEstablished {
        /// Identity of the peer that we have connected to.
        peer_id: PeerId,
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Endpoint of the connection that has been opened.
        endpoint: ConnectedPoint,
        /// Number of established connections to this peer, including the one that has just been
        /// opened.
        num_established: std::num::NonZeroU32,
        /// [`Some`] when the new connection is an outgoing connection.
        /// Addresses are dialed concurrently. Contains the addresses and errors
        /// of dial attempts that failed before the one successful dial.
        concurrent_dial_errors: Option<Vec<(Multiaddr, TransportError<io::Error>)>>,
        /// How long it took to establish this connection
        established_in: std::time::Duration,
    },
}

impl<B> TryFrom<SwarmEvent<B>> for MallorySwarmEvent {
    type Error = SwarmEvent<B>;

    fn try_from(event: SwarmEvent<B>) -> Result<MallorySwarmEvent, Self::Error> {
        match event {
            SwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                reason,
            } => Ok(MallorySwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                reason,
            }),
            SwarmEvent::ListenerError { listener_id, error } => {
                Ok(MallorySwarmEvent::ListenerError { listener_id, error })
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => Ok(MallorySwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            }),
            SwarmEvent::IncomingConnection {
                connection_id,
                local_addr,
                send_back_addr,
            } => Ok(MallorySwarmEvent::IncomingConnection {
                connection_id,
                local_addr,
                send_back_addr,
            }),
            SwarmEvent::IncomingConnectionError {
                connection_id,
                local_addr,
                send_back_addr,
                error,
            } => Ok(MallorySwarmEvent::IncomingConnectionError {
                connection_id,
                local_addr,
                send_back_addr,
                error,
            }),
            SwarmEvent::Dialing {
                peer_id,
                connection_id,
            } => Ok(MallorySwarmEvent::Dialing {
                peer_id,
                connection_id,
            }),
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                cause,
            } => Ok(MallorySwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                cause: cause.map(|v| format!("{:?}", v)),
            }),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                concurrent_dial_errors,
                established_in,
            } => Ok(MallorySwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                concurrent_dial_errors,
                established_in,
            }),
            ev => Err(ev), // Don't pass other events up.
        }
    }
}
// Used for Mallory
