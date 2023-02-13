use std::task::{Context, Poll};

use futures::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::dummy::ConnectionHandler;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction, PollParameters};
use libp2p::PeerId;
use slog::{debug, error};
use types::EthSpec;

use crate::metrics;
use crate::rpc::GoodbyeReason;
use crate::types::SyncState;

use super::peerdb::BanResult;
use super::{ConnectingType, PeerManager, PeerManagerEvent, ReportSource};

impl<TSpec: EthSpec> NetworkBehaviour for PeerManager<TSpec> {
    type ConnectionHandler = ConnectionHandler;

    type OutEvent = PeerManagerEvent;

    /* Required trait members */

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        ConnectionHandler
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        // perform the heartbeat when necessary
        while self.heartbeat.poll_tick(cx).is_ready() {
            self.heartbeat();
        }

        // poll the timeouts for pings and status'
        loop {
            match self.inbound_ping_peers.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(peer_id))) => {
                    self.inbound_ping_peers.insert(peer_id);
                    self.events.push(PeerManagerEvent::Ping(peer_id));
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(self.log, "Failed to check for inbound peers to ping"; "error" => e.to_string())
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        loop {
            match self.outbound_ping_peers.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(peer_id))) => {
                    self.outbound_ping_peers.insert(peer_id);
                    self.events.push(PeerManagerEvent::Ping(peer_id));
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(self.log, "Failed to check for outbound peers to ping"; "error" => e.to_string())
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        if !matches!(
            self.network_globals.sync_state(),
            SyncState::SyncingFinalized { .. } | SyncState::SyncingHead { .. }
        ) {
            loop {
                match self.status_peers.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(peer_id))) => {
                        self.status_peers.insert(peer_id);
                        self.events.push(PeerManagerEvent::Status(peer_id))
                    }
                    Poll::Ready(Some(Err(e))) => {
                        error!(self.log, "Failed to check for peers to ping"; "error" => e.to_string())
                    }
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }
        }

        if !self.events.is_empty() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
        } else {
            self.events.shrink_to_fit();
        }

        if let Some((peer_id, maybe_enr)) = self.peers_to_dial.pop_front() {
            self.inject_peer_connection(&peer_id, ConnectingType::Dialing, maybe_enr);
            let handler = self.new_handler();
            return Poll::Ready(NetworkBehaviourAction::Dial {
                opts: DialOpts::peer_id(peer_id)
                    .condition(PeerCondition::Disconnected)
                    .build(),
                handler,
            });
        }

        Poll::Pending
    }

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                endpoint,
                other_established,
                ..
            }) => self.on_connection_established(peer_id, endpoint, other_established),
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                remaining_established,
                ..
            }) => self.on_connection_closed(peer_id, remaining_established),
            FromSwarm::DialFailure(DialFailure { peer_id, .. }) => self.on_dial_failure(peer_id),
            FromSwarm::AddressChange(_)
            | FromSwarm::ListenFailure(_)
            | FromSwarm::NewListener(_)
            | FromSwarm::NewListenAddr(_)
            | FromSwarm::ExpiredListenAddr(_)
            | FromSwarm::ListenerError(_)
            | FromSwarm::ListenerClosed(_)
            | FromSwarm::NewExternalAddr(_)
            | FromSwarm::ExpiredExternalAddr(_) => {
                // The rest of the events we ignore since they are handled in their associated
                // `SwarmEvent`
            }
        }
    }
}

impl<TSpec: EthSpec> PeerManager<TSpec> {
    fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: &ConnectedPoint,
        other_established: usize,
    ) {
        debug!(self.log, "Connection established"; "peer_id" => %peer_id, "connection" => ?endpoint.to_endpoint());
        if other_established == 0 {
            self.events.push(PeerManagerEvent::MetaData(peer_id));
        }

        // Check NAT if metrics are enabled
        if self.network_globals.local_enr.read().udp4().is_some() {
            metrics::check_nat();
        }

        // Check to make sure the peer is not supposed to be banned
        match self.ban_status(&peer_id) {
            // TODO: directly emit the ban event?
            BanResult::BadScore => {
                // This is a faulty state
                error!(self.log, "Connected to a banned peer. Re-banning"; "peer_id" => %peer_id);
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

        // Count dialing peers in the limit if the peer dialied us.
        let count_dialing = endpoint.is_listener();
        // Check the connection limits
        if self.peer_limit_reached(count_dialing)
            && self
                .network_globals
                .peers
                .read()
                .peer_info(&peer_id)
                .map_or(true, |peer| !peer.has_future_duty())
        {
            // Gracefully disconnect the peer.
            self.disconnect_peer(peer_id, GoodbyeReason::TooManyPeers);
            return;
        }

        // NOTE: We don't register peers that we are disconnecting immediately. The network service
        // does not need to know about these peers.
        match endpoint {
            ConnectedPoint::Listener { send_back_addr, .. } => {
                self.inject_connect_ingoing(&peer_id, send_back_addr.clone(), None);
                self.events
                    .push(PeerManagerEvent::PeerConnectedIncoming(peer_id));
            }
            ConnectedPoint::Dialer { address, .. } => {
                self.inject_connect_outgoing(&peer_id, address.clone(), None);
                self.events
                    .push(PeerManagerEvent::PeerConnectedOutgoing(peer_id));
            }
        }

        // increment prometheus metrics
        self.update_connected_peer_metrics();
        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
    }

    fn on_connection_closed(&mut self, peer_id: PeerId, remaining_established: usize) {
        if remaining_established > 0 {
            return;
        }

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
                .push(PeerManagerEvent::PeerDisconnected(peer_id));
            debug!(self.log, "Peer disconnected"; "peer_id" => %peer_id);
        }

        // NOTE: It may be the case that a rejected node, due to too many peers is disconnected
        // here and the peer manager has no knowledge of its connection. We insert it here for
        // reference so that peer manager can track this peer.
        self.inject_disconnect(&peer_id);

        // Update the prometheus metrics
        self.update_connected_peer_metrics();
        metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
    }

    /// A dial attempt has failed.
    ///
    /// NOTE: It can be the case that we are dialing a peer and during the dialing process the peer
    /// connects and the dial attempt later fails. To handle this, we only update the peer_db if
    /// the peer is not already connected.
    fn on_dial_failure(&mut self, peer_id: Option<PeerId>) {
        if let Some(peer_id) = peer_id {
            if !self.network_globals.peers.read().is_connected(&peer_id) {
                self.inject_disconnect(&peer_id);
            }
        }
    }
}
