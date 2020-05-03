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
    SubstreamProtocol,
};
use libp2p::{Multiaddr, PeerId};
pub use methods::{
    ErrorMessage, MetaData, RPCCodedResponse, RPCResponse, RPCResponseErrorCode, RequestId,
    ResponseTermination, StatusMessage,
};
pub use protocol::{Protocol, RPCError, RPCProtocol, RPCRequest};
use slog::{debug, o};
use std::marker::PhantomData;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use types::EthSpec;

pub(crate) mod codec;
mod handler;
pub mod methods;
mod protocol;

/// The return type used in the behaviour and the resultant event from the protocols handler.
#[derive(Debug)]
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
pub struct RPC<TSubstream, TSpec: EthSpec> {
    /// Queue of events to processed.
    events: Vec<NetworkBehaviourAction<RPCEvent<TSpec>, RPCMessage<TSpec>>>,
    /// Pins the generic substream.
    marker: PhantomData<TSubstream>,
    /// Slog logger for RPC behaviour.
    log: slog::Logger,
}

impl<TSubstream, TSpec: EthSpec> RPC<TSubstream, TSpec> {
    pub fn new(log: slog::Logger) -> Self {
        let log = log.new(o!("service" => "libp2p_rpc"));
        RPC {
            events: Vec::new(),
            marker: PhantomData,
            log,
        }
    }

    /// Submits an RPC request.
    ///
    /// The peer must be connected for this to succeed.
    pub fn send_rpc(&mut self, peer_id: PeerId, rpc_event: RPCEvent<TSpec>) {
        self.events.push(NetworkBehaviourAction::SendEvent {
            peer_id,
            event: rpc_event,
        });
    }
}

impl<TSubstream, TSpec> NetworkBehaviour for RPC<TSubstream, TSpec>
where
    TSubstream: AsyncRead + AsyncWrite,
    TSpec: EthSpec,
{
    type ProtocolsHandler = RPCHandler<TSubstream, TSpec>;
    type OutEvent = RPCMessage<TSpec>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        RPCHandler::new(
            SubstreamProtocol::new(RPCProtocol {
                phantom: PhantomData,
            }),
            Duration::from_secs(30),
            &self.log,
        )
    }

    // handled by discovery
    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, peer_id: PeerId, connected_point: ConnectedPoint) {
        // TODO: Remove this on proper peer discovery
        self.events.push(NetworkBehaviourAction::GenerateEvent(
            RPCMessage::PeerConnectedHack(peer_id.clone(), connected_point.clone()),
        ));
        // if initialised the connection, report this upwards to send the HELLO request
        if let ConnectedPoint::Dialer { .. } = connected_point {
            self.events.push(NetworkBehaviourAction::GenerateEvent(
                RPCMessage::PeerDialed(peer_id.clone()),
            ));
        }

        // find the peer's meta-data
        debug!(self.log, "Requesting new peer's metadata"; "peer_id" => format!("{}",peer_id));
        let rpc_event =
            RPCEvent::Request(RequestId::from(0usize), RPCRequest::MetaData(PhantomData));
        self.events.push(NetworkBehaviourAction::SendEvent {
            peer_id,
            event: rpc_event,
        });
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, connected_point: ConnectedPoint) {
        // TODO: Remove this on proper peer discovery
        self.events.push(NetworkBehaviourAction::GenerateEvent(
            RPCMessage::PeerDisconnectedHack(peer_id.clone(), connected_point.clone()),
        ));

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
pub enum RPCMessage<TSpec: EthSpec> {
    RPC(PeerId, RPCEvent<TSpec>),
    PeerDialed(PeerId),
    PeerDisconnected(PeerId),
    // TODO: This is a hack to give access to connections to peer manager. Remove this once
    // behaviour is re-written
    PeerConnectedHack(PeerId, ConnectedPoint),
    PeerDisconnectedHack(PeerId, ConnectedPoint),
}
