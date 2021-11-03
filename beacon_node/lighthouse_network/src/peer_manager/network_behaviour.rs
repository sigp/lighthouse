use std::task::{Context, Poll};

use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::protocols_handler::DummyProtocolsHandler;
use libp2p::swarm::{
    DialError, NetworkBehaviour, NetworkBehaviourAction, PollParameters, ProtocolsHandler,
};
use libp2p::{Multiaddr, PeerId};
use slog::{debug, error};
use types::EthSpec;

use crate::metrics;
use crate::rpc::GoodbyeReason;

use super::peerdb::BanResult;
use super::{PeerManager, PeerManagerEvent, ReportSource};

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

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        failed_addresses: Option<&Vec<Multiaddr>>,
    ) {
        // Log the connection
        match &endpoint {
            ConnectedPoint::Listener { .. } => {
                debug!(self.log, "Connection established"; "peer_id" => %peer_id, "connection" => "Incoming");
            }
            ConnectedPoint::Dialer { .. } => {
                debug!(self.log, "Connection established"; "peer_id" => %peer_id, "connection" => "Outgoing");
                // TODO: Ensure we have that address registered.
            }
        }

        // Check to make sure the peer is not supposed to be banned
        match self.ban_status(&peer_id) {
            // TODO: directly emit the ban event?
            BanResult::BadScore => {
                // This is a faulty state
                error!(self.log, "Connecteded to a banned peer, re-banning"; "peer_id" => %peer_id);
                // Reban the peer
                self.goodbye_peer(&peer_id, GoodbyeReason::Banned, ReportSource::PeerManager);
                return;
            }
            BanResult::BannedIp(ip_addr) => {
                // A good peer has connected to us via a banned IP address. We ban the peer and
                // prevent future connections.
                debug!(self.log, "Peer connected via banned IP. Banning"; "peer_id" => %peer_id, "banned_ip" => %ip_addr);
                self.goodbye_peer(&peer_id, GoodbyeReason::BannedIP, ReportSource::PeerManager);
                return;
            }
            BanResult::NotBanned => {}
        }

        // Check the connection limits
        if self.peer_limit_reached()
            && self
                .network_globals
                .peers
                .read()
                .peer_info(&peer_id)
                .map_or(true, |peer| !peer.has_future_duty())
        {
            // Gracefully disconnect the peer.
            self.disconnect_peer(*peer_id, GoodbyeReason::TooManyPeers);
            return;
        }

        // Register the newly connected peer (regardless if we are about to disconnect them).
        // NOTE: We don't register peers that we are disconnecting immediately. The network service
        // does not need to know about these peers.
        // let enr
        match endpoint {
            ConnectedPoint::Listener { send_back_addr, .. } => {
                self.inject_connect_ingoing(&peer_id, send_back_addr.clone(), None);
                self.events
                    .push(PeerManagerEvent::PeerConnectedIncoming(*peer_id));
            }
            ConnectedPoint::Dialer { address } => {
                self.inject_connect_outgoing(&peer_id, address.clone(), None);
                self.events
                    .push(PeerManagerEvent::PeerConnectedOutgoing(*peer_id));
            }
        }

        let connected_peers = self.network_globals.connected_peers() as i64;

        // increment prometheus metrics
        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        metrics::set_gauge(&metrics::PEERS_CONNECTED, connected_peers);
        metrics::set_gauge(&metrics::PEERS_CONNECTED_INTEROP, connected_peers);
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId) {
        // There are no more connections
        if self
            .network_globals
            .peers
            .read()
            .is_connected_or_disconnecting(&peer_id)
        {
            // We are disconnecting the peer or the peer has already been connected.
            // Both these cases, the peer has been previously registered by the peer manager and
            // potentially the application layer.
            // Inform the application.
            self.events
                .push(PeerManagerEvent::PeerDisconnected(*peer_id));
            debug!(self.log, "Peer disconnected"; "peer_id" => %peer_id);

            // Decrement the PEERS_PER_CLIENT metric
            if let Some(kind) = self
                .network_globals
                .peers
                .read()
                .peer_info(&peer_id)
                .map(|info| info.client().kind.clone())
            {
                if let Some(v) =
                    metrics::get_int_gauge(&metrics::PEERS_PER_CLIENT, &[&kind.to_string()])
                {
                    v.dec()
                };
            }
        }

        // NOTE: It may be the case that a rejected node, due to too many peers is disconnected
        // here and the peer manager has no knowledge of its connection. We insert it here for
        // reference so that peer manager can track this peer.
        self.inject_disconnect(&peer_id);

        let connected_peers = self.network_globals.connected_peers() as i64;

        // Update the prometheus metrics
        metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
        metrics::set_gauge(&metrics::PEERS_CONNECTED, connected_peers);
        metrics::set_gauge(&metrics::PEERS_CONNECTED_INTEROP, connected_peers);
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
