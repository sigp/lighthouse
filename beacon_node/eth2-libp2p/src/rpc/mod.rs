//! The Ethereum 2.0 Wire Protocol
//!
//! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
//! direct peer-to-peer communication primarily for sending/receiving chain information for
//! syncing.

use handler::RPCHandler;
use libp2p::core::{connection::ConnectionId, ConnectedPoint};
use libp2p::swarm::{
    protocols_handler::ProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters, SubstreamProtocol,
};
use libp2p::{Multiaddr, PeerId};
pub use methods::{
    MetaData, RPCCodedResponse, RPCResponse, RPCResponseErrorCode, RequestId, ResponseTermination,
    StatusMessage,
};
pub use protocol::{Protocol, RPCError, RPCProtocol, RPCRequest};
use slog::{debug, o};
use std::marker::PhantomData;
use std::task::{Context, Poll};
use std::time::Duration;
use types::EthSpec;

pub(crate) mod codec;
mod handler;
pub mod methods;
mod protocol;

/// The return type used in the behaviour and the resultant event from the protocols handler.
#[derive(Debug, Clone)]
pub enum RPCEvent<T: EthSpec> {
    /// An inbound/outbound request for RPC protocol. The first parameter is a sequential
    /// id which tracks an awaiting substream for the response.
    Request(RequestId, RPCRequest<T>),
    /// A response that is being sent or has been received from the RPC protocol. The first parameter returns
    /// that which was sent with the corresponding request, the second is a single chunk of a
    /// response.
    Response(RequestId, RPCCodedResponse<T>),
    /// An Error occurred.
    Error(RequestId, Protocol, RPCError),
}

/// Messages sent to the user from the RPC protocol.
pub struct RPCMessage<TSpec: EthSpec> {
    /// The peer that sent the message.
    pub peer_id: PeerId,
    /// The message that was sent.
    pub event: RPCEvent<TSpec>,
}

impl<T: EthSpec> RPCEvent<T> {
    pub fn id(&self) -> usize {
        match *self {
            RPCEvent::Request(id, _) => id,
            RPCEvent::Response(id, _) => id,
            RPCEvent::Error(id, _, _) => id,
        }
    }
}

impl<T: EthSpec> std::fmt::Display for RPCEvent<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCEvent::Request(id, req) => write!(f, "RPC Request(id: {}, {})", id, req),
            RPCEvent::Response(id, res) => write!(f, "RPC Response(id: {}, {})", id, res),
            RPCEvent::Error(id, prot, err) => write!(
                f,
                "RPC Error(id: {}, protocol: {:?} error: {:?})",
                id, prot, err
            ),
        }
    }
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<TSpec: EthSpec> {
    /// Queue of events to processed.
    events: Vec<NetworkBehaviourAction<RPCEvent<TSpec>, RPCMessage<TSpec>>>,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
}

impl<TSpec: EthSpec> RPC<TSpec> {
    pub fn new(log: slog::Logger) -> Self {
        let log = log.new(o!("service" => "libp2p_rpc"));
        RPC {
            events: Vec::new(),
            log,
        }
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_rpc(&mut self, peer_id: PeerId, rpc_event: RPCEvent<TSpec>) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event: rpc_event,
        });
    }
}

impl<TSpec> NetworkBehaviour for RPC<TSpec>
where
    TSpec: EthSpec,
{
    type ProtocolsHandler = RPCHandler<TSpec>;
    type OutEvent = RPCMessage<TSpec>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        RPCHandler::new(
            SubstreamProtocol::new(RPCProtocol {
                phantom: PhantomData,
            }),
            Duration::from_secs(5),
            &self.log,
        )
    }

    // handled by discovery
    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    // Use connection established/closed instead of these currently
    fn inject_connected(&mut self, peer_id: &PeerId) {
        // find the peer's meta-data
        debug!(self.log, "Requesting new peer's metadata"; "peer_id" => format!("{}",peer_id));
        let rpc_event =
            RPCEvent::Request(RequestId::from(0usize), RPCRequest::MetaData(PhantomData));
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id: peer_id.clone(),
            handler: NotifyHandler::Any,
            event: rpc_event,
        });
    }

    fn inject_disconnected(&mut self, _peer_id: &PeerId) {}

    fn inject_connection_established(
        &mut self,
        _peer_id: &PeerId,
        _: &ConnectionId,
        _connected_point: &ConnectedPoint,
    ) {
    }

    fn inject_connection_closed(
        &mut self,
        _peer_id: &PeerId,
        _: &ConnectionId,
        _connected_point: &ConnectedPoint,
    ) {
    }

    fn inject_event(
        &mut self,
        source: PeerId,
        _: ConnectionId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        // send the event to the user
        self.events
            .push(NetworkBehaviourAction::GenerateEvent(RPCMessage {
                peer_id: source,
                event,
            }));
    }

    fn poll(
        &mut self,
        _cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }
        Poll::Pending
    }
}
