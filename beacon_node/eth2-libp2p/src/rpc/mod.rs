///! The Ethereum 2.0 Wire Protocol
///!
///! This protocol is a purpose built Ethereum 2.0 libp2p protocol. It's role is to facilitate
///! direct peer-to-peer communication primarily for sending/receiving chain information for
///! syncing.
use futures::prelude::*;
use handler::RPCHandler;
use libp2p::core::protocols_handler::ProtocolsHandler;
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::{Multiaddr, PeerId};
pub use methods::HelloMessage;
pub use protocol::{RPCProtocol, RPCRequest, RPCResponse};
use slog::o;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

mod handler;
pub mod methods;
mod protocol;
mod request_response;

/// The return type used in the behaviour and the resultant event from the protocols handler.
#[derive(Debug, Clone)]
pub enum RPCEvent {
    /// A request that was received from the RPC protocol. The first parameter is a sequential
    /// id which tracks an awaiting substream for the response.
    Request(usize, RPCRequest),

    /// A response that has been received from the RPC protocol. The first parameter returns
    /// that which was sent with the corresponding request.
    Response(usize, RPCResponse),
}

/// Implements the libp2p `NetworkBehaviour` trait and therefore manages network-level
/// logic.
pub struct RPC<TSubstream> {
    /// Queue of events to processed.
    events: Vec<NetworkBehaviourAction<RPCEvent, RPCMessage>>,
    /// Pins the generic substream.
    marker: PhantomData<TSubstream>,
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

    fn inject_disconnected(&mut self, _: &PeerId, _: ConnectedPoint) {}

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
}
