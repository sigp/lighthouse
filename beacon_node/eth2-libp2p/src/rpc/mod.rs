//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use futures::prelude::*;
use handler::RPCHandler;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{
    protocols_handler::ProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::{Multiaddr, PeerId};
pub use methods::{ErrorMessage, HelloMessage, RPCErrorResponse, RPCResponse, RequestId};
pub use protocol::{RPCError, RPCProtocol, RPCRequest};
use slog::o;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) mod codec;
mod handler;
pub mod methods;
mod protocol;
// mod request_response;

/// The return type used in the behaviour and the resultant event from the protocols handler.
#[derive(Debug)]
pub enum RPCEvent {
    /// A request that was received from the RPC protocol. The first parameter is a sequential
    /// id which tracks an awaiting substream for the response.
    Request(RequestId, RPCRequest),

    /// A response that has been received from the RPC protocol. The first parameter returns
    /// that which was sent with the corresponding request.
    Response(RequestId, RPCErrorResponse),
    /// An Error occurred.
    Error(RequestId, RPCError),
}

impl RPCEvent {
    pub fn id(&self) -> usize {
        match *self {
            RPCEvent::Request(id, _) => id,
            RPCEvent::Response(id, _) => id,
            RPCEvent::Error(id, _) => id,
        }
    }
}

impl std::fmt::Display for RPCEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCEvent::Request(id, req) => write!(f, "RPC Request(Id: {}, {})", id, req),
            RPCEvent::Response(id, res) => write!(f, "RPC Response(Id: {}, {})", id, res),
            RPCEvent::Error(id, err) => write!(f, "RPC Request(Id: {}, Error: {:?})", id, err),
        }
    }
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<TSubstream> {
    /// Queue of events to processed.
    events: Vec<NetworkBehaviourAction<RPCEvent, RPCMessage>>,
    /// Pins the generic substream.
    marker: PhantomData<(TSubstream)>,
    /// Slog logger for RPC behaviour.
    _log: slog::Logger,
}

impl<TSubstream> RPC<TSubstream> {
    pub fn new(log: &slog::Logger) -> Self {
        let log = log.new(o!("Service" => "Libp2p-RPC"));
        RPC {
            events: Vec::new(),
            marker: PhantomData,
            _log: log,
        }
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_rpc(&mut self, peer_id: PeerId, rpc_event: RPCEvent) {
        self.events.push(NetworkBehaviourAction::SendEvent {
            peer_id,
            event: rpc_event,
        });
    }
}

impl<TSubstream> NetworkBehaviour for RPC<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = RPCHandler<TSubstream>;
    type OutEvent = RPCMessage;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        Default::default()
    }

    // handled by discovery
    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, peer_id: PeerId, connected_point: ConnectedPoint) {
        // if initialised the connection, report this upwards to send the HELLO request
        if let ConnectedPoint::Dialer { .. } = connected_point {
            self.events.push(NetworkBehaviourAction::GenerateEvent(
                RPCMessage::PeerDialed(peer_id),
            ));
        }
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, _: ConnectedPoint) {
        // inform the rpc handler that the peer has disconnected
        self.events.push(NetworkBehaviourAction::GenerateEvent(
            RPCMessage::PeerDisconnected(peer_id.clone()),
        ));
    }

    fn inject_node_event(
        &mut self,
        source: PeerId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        // send the event to the user
        self.events
            .push(NetworkBehaviourAction::GenerateEvent(RPCMessage::RPC(
                source, event,
            )));
    }

    fn poll(
        &mut self,
        _: &mut impl PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        if !self.events.is_empty() {
            return Async::Ready(self.events.remove(0));
        }
        Async::NotReady
    }
}

/// Messages sent to the user from the RPC protocol.
pub enum RPCMessage {
    RPC(PeerId, RPCEvent),
    PeerDialed(PeerId),
    PeerDisconnected(PeerId),
}
