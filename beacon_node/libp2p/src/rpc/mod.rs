mod handler;
mod methods;
/// RPC Protocol over libp2p.
///
/// This is purpose built for Ethereum 2.0 serenity and the protocol listens on
/// `/eth/serenity/rpc/1.0.0`
mod protocol;

use futures::prelude::*;
use libp2p::core::protocols_handler::{OneShotHandler, ProtocolsHandler};
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::{Multiaddr, PeerId};
use methods::RPCRequest;
use protocol::{RPCProtocol, RpcEvent};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

/// The network behaviour handles RPC requests/responses as specified in the Eth 2.0 phase 0
/// specification.

pub struct Rpc<TSubstream> {
    /// Queue of events to processed.
    events: Vec<RpcEvent>,
    /// Pins the generic substream.
    marker: PhantomData<TSubstream>,
}

impl<TSubstream> Rpc<TSubstream> {
    pub fn new() -> Self {
        Rpc {
            events: Vec::new(),
            marker: PhantomData,
        }
    }

    /// Submits and RPC request.
    pub fn send_request(&mut self, id: u64, method_id: u16, body: RPCRequest) {
        let request = RpcEvent::Request {
            id,
            method_id,
            body,
        };
        self.events.push(request);
    }
}

impl<TSubstream> NetworkBehaviour for Rpc<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = OneShotHandler<TSubstream, RPCProtocol, RpcEvent, OneShotEvent>;
    type OutEvent = RpcEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        Default::default()
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn inject_connected(&mut self, _: PeerId, _: ConnectedPoint) {}

    fn inject_disconnected(&mut self, _: &PeerId, _: ConnectedPoint) {}

    fn inject_node_event(
        &mut self,
        source: PeerId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        // ignore successful sends event
        let event = match event {
            OneShotEvent::Rx(event) => event,
            OneShotEvent::Sent => return,
        };

        // send the event to the user
        self.events.push(event);
    }

    fn poll(
        &mut self,
        _: &mut PollParameters<'_>,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        if !self.events.is_empty() {
            return Async::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
        }
        Async::NotReady
    }
}

/// Transmission between the `OneShotHandler` and the `RpcEvent`.
#[derive(Debug)]
pub enum OneShotEvent {
    /// We received an RPC from a remote.
    Rx(RpcEvent),
    /// We successfully sent an RPC request.
    Sent,
}

impl From<RpcEvent> for OneShotEvent {
    #[inline]
    fn from(rpc: RpcEvent) -> OneShotEvent {
        OneShotEvent::Rx(rpc)
    }
}

impl From<()> for OneShotEvent {
    #[inline]
    fn from(_: ()) -> OneShotEvent {
        OneShotEvent::Sent
    }
}
