use std::task::Context;
use std::task::Poll;

use super::PeerManager;
use super::PeerManagerEvent;
use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::protocols_handler::DummyProtocolsHandler;
use libp2p::swarm::protocols_handler::ProtocolsHandler;
use libp2p::swarm::NetworkBehaviour;
use libp2p::Multiaddr;
use libp2p::PeerId;
use types::EthSpec;

impl<TSpec: EthSpec> NetworkBehaviour for PeerManager<TSpec> {
    type ProtocolsHandler = DummyProtocolsHandler;

    type OutEvent = PeerManagerEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DummyProtocolsHandler::default()
    }

    fn inject_event(
        &mut self,
        _peer_id: PeerId,
        _connection: ConnectionId,
        _event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
    }

    /// Dialing attempt.
    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        // NOTE: This method is called when starting a dial attempt. This has been the case for
        // some time but it is not documented or guaranteed to remain this way.
        vec![]
    }

    /// Dialing failure.
    fn inject_dial_failure(&mut self, peer_id: &PeerId) {}

    /// Peer connected
    fn inject_connection_established(&mut self, _: &PeerId, _: &ConnectionId, _: &ConnectedPoint) {}

    /// Peer disconneted
    fn inject_connection_closed(&mut self, peer_id: &PeerId, _: &ConnectionId, _: &ConnectedPoint) {
    }

    /// Informs the behaviour that the [`ConnectedPoint`] of an existing connection has changed.
    fn inject_address_change(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _old: &ConnectedPoint,
        _new: &ConnectedPoint,
    ) {
        // check that old and new do not change type
    }


    fn poll(&mut self, cx: &mut Context<'_>, params: &mut impl libp2p::swarm::PollParameters)
    -> Poll<libp2p::swarm::NetworkBehaviourAction<<<Self::ProtocolsHandler as libp2p::swarm::IntoProtocolsHandler>::Handler as libp2p::swarm::ProtocolsHandler>::InEvent, Self::OutEvent>>{
        todo!()
    }
}
