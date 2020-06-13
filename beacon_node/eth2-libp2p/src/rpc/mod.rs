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
use slog::{debug, o};
use std::marker::PhantomData;
use std::task::{Context, Poll};
use std::time::Duration;
use types::EthSpec;

pub(crate) use handler::HandlerErr;
pub(crate) use methods::{MetaData, Ping, RPCCodedResponse, RPCResponse};
pub(crate) use protocol::{RPCProtocol, RPCRequest};

pub use handler::SubstreamId;
pub use methods::{
    BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason, MaxRequestBlocks,
    RPCResponseErrorCode, RequestId, ResponseTermination, StatusMessage, MAX_REQUEST_BLOCKS,
};
pub use protocol::{Protocol, RPCError};

pub(crate) mod codec;
mod handler;
pub mod methods;
mod protocol;

/// RPC events sent from Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCSend<T: EthSpec> {
    /// A request sent from Lighthouse.
    ///
    /// The `RequestId` is given by the application making the request. These
    /// go over *outbound* connections.
    Request(RequestId, RPCRequest<T>),
    /// A response sent from Lighthouse.
    ///
    /// The `SubstreamId` must correspond to the RPC-given ID of the original request received from the
    /// peer. The second parameter is a single chunk of a response. These go over *inbound*
    /// connections.
    Response(SubstreamId, RPCCodedResponse<T>),
}

/// RPC events received from outside Lighthouse.
#[derive(Debug, Clone)]
pub enum RPCReceived<T: EthSpec> {
    /// A request received from the outside.
    ///
    /// The `SubstreamId` is given by the `RPCHandler` as it identifies this request with the
    /// *inbound* substream over which it is managed.
    Request(SubstreamId, RPCRequest<T>),
    /// A response received from the outside.
    ///
    /// The `RequestId` corresponds to the application given ID of the original request sent to the
    /// peer. The second parameter is a single chunk of a response. These go over *outbound*
    /// connections.
    Response(RequestId, RPCResponse<T>),
    /// Marks a request as completed
    EndOfStream(RequestId, ResponseTermination),
}

impl<T: EthSpec> std::fmt::Display for RPCSend<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RPCSend::Request(id, req) => write!(f, "RPC Request(id: {:?}, {})", id, req),
            RPCSend::Response(id, res) => write!(f, "RPC Response(id: {:?}, {})", id, res),
        }
    }
}

/// Messages sent to the user from the RPC protocol.
pub struct RPCMessage<TSpec: EthSpec> {
    /// The peer that sent the message.
    pub peer_id: PeerId,
    /// The message that was sent.
    pub event: <RPCHandler<TSpec> as ProtocolsHandler>::OutEvent,
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<TSpec: EthSpec> {
    /// Queue of events to be processed.
    events: Vec<NetworkBehaviourAction<RPCSend<TSpec>, RPCMessage<TSpec>>>,
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
    pub fn send_rpc(&mut self, peer_id: PeerId, event: RPCSend<TSpec>) {
        self.events.push(NetworkBehaviourAction::NotifyHandler {
            peer_id,
            handler: NotifyHandler::Any,
            event,
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
        let rpc_event = RPCSend::Request(RequestId::Behaviour, RPCRequest::MetaData(PhantomData));
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
        peer_id: PeerId,
        _: ConnectionId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        // send the event to the user
        self.events
            .push(NetworkBehaviourAction::GenerateEvent(RPCMessage {
                peer_id,
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
