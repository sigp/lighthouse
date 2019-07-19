/// RPC Protocol over libp2p.
///
/// This is purpose built for Ethereum 2.0 serenity and the protocol listens on
/// `/eth/serenity/rpc/1.0.0`
pub mod methods;
mod protocol;

use futures::prelude::*;
use libp2p::core::protocols_handler::{OneShotHandler, ProtocolsHandler};
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::{Multiaddr, PeerId};
pub use methods::{HelloMessage, RPCMethod, RPCRequest, RPCResponse};
pub use protocol::{RPCEvent, RPCProtocol, RequestId};
use slog::o;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};
use types::EthSpec;

/// The network behaviour handles RPC requests/responses as specified in the Eth 2.0 phase 0
/// specification.

pub struct Rpc<TSubstream, E: EthSpec> {
    /// Queue of events to processed.
    events: Vec<NetworkBehaviourAction<RPCEvent<E>, RPCMessage<E>>>,
    /// Pins the generic substream.
    marker: PhantomData<TSubstream>,
    /// Slog logger for RPC behaviour.
    _log: slog::Logger,
}

impl<TSubstream, E: EthSpec> Rpc<TSubstream, E> {
    pub fn new(log: &slog::Logger) -> Self {
        let log = log.new(o!("Service" => "Libp2p-RPC"));
        Rpc {
            events: Vec::new(),
            marker: PhantomData,
            _log: log,
        }
    }

    /// Submits and RPC request.
    pub fn send_rpc(&mut self, peer_id: PeerId, rpc_event: RPCEvent<E>) {
        self.events.push(NetworkBehaviourAction::SendEvent {
            peer_id,
            event: rpc_event,
        });
    }
}

impl<TSubstream, E> NetworkBehaviour for Rpc<TSubstream, E>
where
    TSubstream: AsyncRead + AsyncWrite,
    E: EthSpec,
{
    type ProtocolsHandler =
        OneShotHandler<TSubstream, RPCProtocol<E>, RPCEvent<E>, OneShotEvent<E>>;
    type OutEvent = RPCMessage<E>;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        Default::default()
    }

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
        // ignore successful send events
        let event = match event {
            OneShotEvent::Rx(event) => event,
            OneShotEvent::Sent => return,
        };

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
pub enum RPCMessage<E: EthSpec> {
    RPC(PeerId, RPCEvent<E>),
    PeerDialed(PeerId),
}

/// Transmission between the `OneShotHandler` and the `RPCEvent`.
#[derive(Debug)]
pub enum OneShotEvent<E: EthSpec> {
    /// We received an RPC from a remote.
    Rx(RPCEvent<E>),
    /// We successfully sent an RPC request.
    Sent,
}

impl<E: EthSpec> From<RPCEvent<E>> for OneShotEvent<E> {
    #[inline]
    fn from(rpc: RPCEvent<E>) -> Self {
        OneShotEvent::Rx(rpc)
    }
}

impl<E: EthSpec> From<()> for OneShotEvent<E> {
    #[inline]
    fn from(_: ()) -> Self {
        OneShotEvent::Sent
    }
}
