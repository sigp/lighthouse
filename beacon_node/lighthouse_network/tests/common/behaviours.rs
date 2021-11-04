use std::collections::{HashMap, VecDeque};

use futures::task::{Context, Poll};
use futures::StreamExt;
use libp2p::core::connection::{ConnectionId, ListenerId};
use libp2p::swarm::protocols_handler::{DummyProtocolsHandler, ProtocolsHandler};
use libp2p::swarm::{DialError, NetworkBehaviour, PollParameters, SwarmEvent};
use libp2p::PeerId;
use lighthouse_network::{ConnectedPoint, Multiaddr};

pub use libp2p::swarm::NetworkBehaviourAction as NBAction;

/// Calls the swarm makes to the Behaviour.
#[derive(PartialEq, Eq, Hash, Debug)]
pub enum MethodCall {
    AddressesOfPeer,
    InjectConnected,
    InjectDisconnected,
    InjectConnectionEstablished,
    InjectConnectionClosed,
    InjectAddressChange,
    InjectListenFailure,
    InjectDialFailure,
    InjectNewListener,
    InjectNewListenAddr,
    InjectExpiredListenAddr,
    InjectListenerError,
    InjectListenerClosed,
    InjectNewExternalAddr,
    InjectExpiredExternalAddr,
}

pub type PuppetEvent = NBAction<(), DummyProtocolsHandler>;

/// Behaviour used to generate events for the swarm.
#[derive(Default)]
pub struct PuppetBehaviour {
    events: VecDeque<PuppetEvent>,
    // Number of times the swarm functions have been called. This is useful for debugging.
    call_counts: HashMap<MethodCall, usize>,
}

impl PuppetBehaviour {
    pub fn queue_event(&mut self, ev: PuppetEvent) {
        self.events.push_back(ev)
    }

    pub fn calls(&self) -> &HashMap<MethodCall, usize> {
        &self.call_counts
    }

    fn register_call(&mut self, call: MethodCall) {
        *self.call_counts.entry(call).or_default() += 1;
    }
}

impl NetworkBehaviour for PuppetBehaviour {
    type ProtocolsHandler = DummyProtocolsHandler;

    type OutEvent = ();

    /* Required members */

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DummyProtocolsHandler {
            keep_alive: libp2p::swarm::KeepAlive::Yes,
        }
    }

    fn inject_event(
        &mut self,
        _peer_id: PeerId,
        _connection: ConnectionId,
        _event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        unreachable!("Dummy handler produces no events")
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<NBAction<Self::OutEvent, Self::ProtocolsHandler>> {
        self.events.pop_front().map_or(Poll::Pending, Poll::Ready)
    }

    /* Overwritten default trait members */

    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        self.register_call(MethodCall::AddressesOfPeer);
        vec![]
    }

    fn inject_connected(&mut self, _: &PeerId) {
        self.register_call(MethodCall::InjectConnected)
    }

    fn inject_disconnected(&mut self, _: &PeerId) {
        self.register_call(MethodCall::InjectDisconnected)
    }

    fn inject_connection_established(
        &mut self,
        _peer_id: &PeerId,
        _connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
    ) {
        self.register_call(MethodCall::InjectConnectionEstablished)
    }

    fn inject_connection_closed(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _: &ConnectedPoint,
        _: Self::ProtocolsHandler,
    ) {
        self.register_call(MethodCall::InjectConnectionClosed)
    }

    fn inject_address_change(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _old: &ConnectedPoint,
        _new: &ConnectedPoint,
    ) {
        self.register_call(MethodCall::InjectAddressChange)
    }

    fn inject_dial_failure(
        &mut self,
        _peer_id: Option<PeerId>,
        _handler: Self::ProtocolsHandler,
        _error: &DialError,
    ) {
        self.register_call(MethodCall::InjectDialFailure)
    }

    fn inject_listen_failure(
        &mut self,
        _local_addr: &Multiaddr,
        _send_back_addr: &Multiaddr,
        _handler: Self::ProtocolsHandler,
    ) {
        self.register_call(MethodCall::InjectListenFailure)
    }

    fn inject_new_listener(&mut self, _id: ListenerId) {
        self.register_call(MethodCall::InjectNewListener)
    }

    fn inject_new_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {
        self.register_call(MethodCall::InjectNewListenAddr)
    }

    fn inject_expired_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {
        self.register_call(MethodCall::InjectExpiredListenAddr)
    }

    fn inject_listener_error(&mut self, _id: ListenerId, _err: &(dyn std::error::Error + 'static)) {
        self.register_call(MethodCall::InjectListenerError)
    }

    fn inject_listener_closed(&mut self, _id: ListenerId, _reason: Result<(), &std::io::Error>) {
        self.register_call(MethodCall::InjectListenerClosed)
    }

    fn inject_new_external_addr(&mut self, _addr: &Multiaddr) {
        self.register_call(MethodCall::InjectNewExternalAddr)
    }

    fn inject_expired_external_addr(&mut self, _addr: &Multiaddr) {
        self.register_call(MethodCall::InjectExpiredExternalAddr)
    }
}

/// Bind this swarm to a random listener. This must be called before any other interaction with the
/// swarm.
pub async fn bind_listener<T: libp2p::swarm::NetworkBehaviour>(
    swarm: &mut libp2p::Swarm<T>,
) -> Multiaddr {
    swarm.listen_on(crate::common::local_multiaddr()).unwrap();

    match swarm.select_next_some().await {
        SwarmEvent::NewListenAddr { address, .. } => address,
        _ => unreachable!(),
    }
}
