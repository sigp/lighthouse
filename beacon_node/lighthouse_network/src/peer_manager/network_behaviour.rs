//! Implementation of [`NetworkBehaviour`] for the [`PeerManager`].

use std::net::IpAddr;
use std::task::{Context, Poll};

use futures::StreamExt;
use libp2p::core::transport::PortUse;
use libp2p::core::ConnectedPoint;
use libp2p::identity::PeerId;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::dummy::ConnectionHandler;
use libp2p::swarm::{ConnectionDenied, ConnectionId, NetworkBehaviour, ToSwarm};
pub use metrics::{set_gauge_vec, NAT_OPEN};
use slog::{debug, error, trace};
use types::EthSpec;

use crate::discovery::enr_ext::EnrExt;
use crate::types::SyncState;
use crate::{metrics, ClearDialError};

use super::{ConnectingType, PeerManager, PeerManagerEvent};

impl<E: EthSpec> NetworkBehaviour for PeerManager<E> {
    type ConnectionHandler = ConnectionHandler;
    type ToSwarm = PeerManagerEvent;

    /* Required trait members */

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        // no events from the dummy handler
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, void::Void>> {
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
            return Poll::Ready(ToSwarm::GenerateEvent(self.events.remove(0)));
        } else {
            self.events.shrink_to_fit();
        }

        if let Some(enr) = self.peers_to_dial.pop() {
            self.inject_peer_connection(&enr.peer_id(), ConnectingType::Dialing, Some(enr.clone()));

            // Prioritize Quic connections over Tcp ones.
            let multiaddrs = [
                self.quic_enabled
                    .then_some(enr.multiaddr_quic())
                    .unwrap_or_default(),
                enr.multiaddr_tcp(),
            ]
            .concat();

            debug!(self.log, "Dialing peer"; "peer_id"=> %enr.peer_id(), "multiaddrs" => ?multiaddrs);
            return Poll::Ready(ToSwarm::Dial {
                opts: DialOpts::peer_id(enr.peer_id())
                    .condition(PeerCondition::Disconnected)
                    .addresses(multiaddrs)
                    .build(),
            });
        }

        Poll::Pending
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                endpoint,
                other_established,
                ..
            }) => self.on_connection_established(peer_id, endpoint, other_established),
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                endpoint,

                remaining_established,
                ..
            }) => self.on_connection_closed(peer_id, endpoint, remaining_established),
            FromSwarm::DialFailure(DialFailure {
                peer_id,
                error,
                connection_id: _,
            }) => {
                debug!(self.log, "Failed to dial peer"; "peer_id"=> ?peer_id, "error" => %ClearDialError(error));
                self.on_dial_failure(peer_id);
            }
            FromSwarm::ExternalAddrConfirmed(_) => {
                // We have an external address confirmed, means we are able to do NAT traversal.
                metrics::set_gauge_vec(&metrics::NAT_OPEN, &["libp2p"], 1);
            }
            _ => {
                // NOTE: FromSwarm is a non exhaustive enum so updates should be based on release
                // notes more than compiler feedback
                // The rest of the events we ignore since they are handled in their associated
                // `SwarmEvent`
            }
        }
    }

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // get the IP address to verify it's not banned.
        let ip = match remote_addr.iter().next() {
            Some(Protocol::Ip6(ip)) => IpAddr::V6(ip),
            Some(Protocol::Ip4(ip)) => IpAddr::V4(ip),
            _ => {
                return Err(ConnectionDenied::new(format!(
                    "Connection to peer rejected: invalid multiaddr: {remote_addr}"
                )))
            }
        };

        if self.network_globals.peers.read().is_ip_banned(&ip) {
            return Err(ConnectionDenied::new(format!(
                "Connection to peer rejected: peer {ip} is banned"
            )));
        }

        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer_id: PeerId,
        _local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, ConnectionDenied> {
        trace!(self.log, "Inbound connection"; "peer_id" => %peer_id, "multiaddr" => %remote_addr);
        // We already checked if the peer was banned on `handle_pending_inbound_connection`.
        if self.ban_status(&peer_id).is_some() {
            return Err(ConnectionDenied::new(
                "Connection to peer rejected: peer has a bad score",
            ));
        }

        // Check the connection limits
        if self.network_globals.connected_or_dialing_peers() >= self.max_peers()
            && self
                .network_globals
                .peers
                .read()
                .peer_info(&peer_id)
                .map_or(true, |peer| !peer.has_future_duty())
        {
            return Err(ConnectionDenied::new(
                "Connection to peer rejected: too many connections",
            ));
        }

        // We have an inbound connection, this is indicative of having our libp2p NAT ports open. We
        // distinguish between ipv4 and ipv6 here:
        match remote_addr.iter().next() {
            Some(Protocol::Ip4(_)) => set_gauge_vec(&NAT_OPEN, &["libp2p_ipv4"], 1),
            Some(Protocol::Ip6(_)) => set_gauge_vec(&NAT_OPEN, &["libp2p_ipv6"], 1),
            _ => {}
        }

        Ok(ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer_id: PeerId,
        addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        trace!(self.log, "Outbound connection"; "peer_id" => %peer_id, "multiaddr" => %addr);
        if let Some(cause) = self.ban_status(&peer_id) {
            error!(self.log, "Connected a banned peer. Rejecting connection"; "peer_id" => %peer_id);
            return Err(ConnectionDenied::new(cause));
        }

        // Check the connection limits
        if self.network_globals.connected_peers() >= self.max_outbound_dialing_peers()
            && self
                .network_globals
                .peers
                .read()
                .peer_info(&peer_id)
                .map_or(true, |peer| !peer.has_future_duty())
        {
            return Err(ConnectionDenied::new(
                "Connection to peer rejected: too many connections",
            ));
        }

        Ok(ConnectionHandler)
    }
}

impl<E: EthSpec> PeerManager<E> {
    fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: &ConnectedPoint,
        _other_established: usize,
    ) {
        debug!(self.log, "Connection established"; "peer_id" => %peer_id,
            "multiaddr" => %endpoint.get_remote_address(),
            "connection" => ?endpoint.to_endpoint()
        );

        // Update the prometheus metrics
        if self.metrics_enabled {
            metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);

            self.update_peer_count_metrics();
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
        };
    }

    fn on_connection_closed(
        &mut self,
        peer_id: PeerId,
        _endpoint: &ConnectedPoint,
        remaining_established: usize,
    ) {
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
        if self.metrics_enabled {
            // Legacy standard metrics.
            metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);

            self.update_peer_count_metrics();
        }
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
