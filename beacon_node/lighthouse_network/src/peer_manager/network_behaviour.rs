use std::task::{Context, Poll};

use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::protocols_handler::DummyProtocolsHandler;
use libp2p::swarm::{
    DialError, NetworkBehaviour, NetworkBehaviourAction, PollParameters, ProtocolsHandler,
};
use libp2p::{Multiaddr, PeerId};
use types::EthSpec;

use crate::PeerManager;

use super::PeerManagerEvent;

impl<TSpec: EthSpec> NetworkBehaviour for PeerManager<TSpec> {
    type ProtocolsHandler = DummyProtocolsHandler;

    type OutEvent = PeerManagerEvent;

    /* Required trait members */

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DummyProtocolsHandler::default()
    }

    fn inject_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        _: <DummyProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        unreachable!("Dummy handler does not emit events")
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ProtocolsHandler>> {
        todo!()
    }

    /* Overwritten trait members */

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        vec![]
    }

    fn inject_connected(&mut self, peer_id: &PeerId) {}

    fn inject_disconnected(&mut self, peer_id: &PeerId) {}

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        failed_addresses: Option<&Vec<Multiaddr>>,
    ) {
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        handler: DummyProtocolsHandler,
    ) {
    }

    fn inject_address_change(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        handler: DummyProtocolsHandler,
        error: &DialError,
    ) {
    }

    fn inject_listen_failure(
        &mut self,
        local_addr: &Multiaddr,
        send_back_addr: &Multiaddr,
        handler: DummyProtocolsHandler,
    ) {
    }
}
