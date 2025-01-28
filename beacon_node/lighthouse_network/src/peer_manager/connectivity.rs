use crate::peer_manager::network_globals_provider::NetworkGlobalsProvider;
use crate::peer_manager::PeerManagerEvent;
use crate::rpc::GoodbyeReason;
use crate::{EnrExt, PeerId};
use discv5::Enr;
use slog::debug;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::time::Instant;

/// A fraction of `PeerManager::target_peers` that we allow to connect to us in excess of
/// `PeerManager::target_peers`. For clarity, if `PeerManager::target_peers` is 50 and
/// PEER_EXCESS_FACTOR = 0.1 we allow 10% more nodes, i.e 55.
pub const PEER_EXCESS_FACTOR: f32 = 0.1;

/// The fraction of extra peers beyond the PEER_EXCESS_FACTOR that we allow us to dial for when
/// requiring subnet peers. More specifically, if our target peer limit is 50, and our excess peer
/// limit is 55, and we are at 55 peers, the following parameter provisions a few more slots of
/// dialing priority peers we need for validator duties.
const PRIORITY_PEER_EXCESS: f32 = 0.2;

/// A fraction of `PeerManager::target_peers` that if we get below, we start a discovery query to
/// reach our target.
pub const MIN_OUTBOUND_ONLY_FACTOR: f32 = 0.2;

pub struct Connectivity<N: NetworkGlobalsProvider> {
    target_peers: usize,
    discovery_enabled: bool,
    /// Peers queued to be dialed.
    peers_to_dial: Vec<Enr>,
    network_globals_provider: N,
    /// The logger associated with the `PeerManager`.
    log: slog::Logger,
}

impl<N: NetworkGlobalsProvider> Connectivity<N> {
    pub fn new(
        target_peers: usize,
        discovery_enabled: bool,
        network_globals_provider: N,
        log: &slog::Logger,
    ) -> Self {
        Self {
            target_peers,
            discovery_enabled,
            peers_to_dial: Default::default(),
            network_globals_provider,
            log: log.clone(),
        }
    }

    /// A peer is being dialed.
    /// Returns true, if this peer will be dialed.
    pub fn dial_peer(&mut self, peer: Enr) -> bool {
        if self.network_globals_provider.should_dial(&peer.peer_id()) {
            self.peers_to_dial.push(peer);
            true
        } else {
            false
        }
    }

    // Gracefully disconnects a peer without banning them.
    pub fn disconnect_peer(
        &mut self,
        peer_id: PeerId,
        reason: GoodbyeReason,
        events: &mut SmallVec<[PeerManagerEvent; 16]>,
    ) {
        events.push(PeerManagerEvent::DisconnectPeer(peer_id, reason));
        self.network_globals_provider
            .notify_disconnecting(&peer_id, false);
    }

    pub fn next_peer_to_dial(&mut self) -> Option<Enr> {
        self.peers_to_dial.pop()
    }

    /// Peers that have been returned by discovery requests that are suitable for dialing are
    /// returned here.
    ///
    /// This function decides whether or not to dial these peers.
    pub fn peers_discovered(
        &mut self,
        results: &HashMap<Enr, Option<Instant>>,
        events: &mut SmallVec<[PeerManagerEvent; 16]>,
    ) {
        let mut to_dial_peers = 0;
        let results_count = results.len();
        let connected_or_dialing = self.network_globals_provider.connected_or_dialing_peers();
        for (enr, min_ttl) in results {
            // There are two conditions in deciding whether to dial this peer.
            // 1. If we are less than our max connections. Discovery queries are executed to reach
            //    our target peers, so its fine to dial up to our max peers (which will get pruned
            //    in the next heartbeat down to our target).
            // 2. If the peer is one our validators require for a specific subnet, then it is
            //    considered a priority. We have pre-allocated some extra priority slots for these
            //    peers as specified by PRIORITY_PEER_EXCESS. Therefore we dial these peers, even
            //    if we are already at our max_peer limit.
            if !self.peers_to_dial.contains(enr)
                && ((min_ttl.is_some()
                    && connected_or_dialing + to_dial_peers < self.max_priority_peers())
                    || connected_or_dialing + to_dial_peers < self.max_peers())
            {
                // This should be updated with the peer dialing. In fact created once the peer is
                // dialed
                let peer_id = enr.peer_id();
                if let Some(min_ttl) = min_ttl {
                    self.network_globals_provider
                        .update_min_ttl(&peer_id, *min_ttl);
                }
                if self.dial_peer(enr.clone()) {
                    debug!(self.log, "Added discovered ENR peer to dial queue"; "peer_id" => %peer_id);
                    to_dial_peers += 1;
                }
            }
        }

        // The heartbeat will attempt new discovery queries every N seconds if the node needs more
        // peers. As an optimization, this function can recursively trigger new discovery queries
        // immediatelly if we don't fulfill our peers needs after completing a query. This
        // recursiveness results in an infinite loop in networks where there not enough peers to
        // reach out target. To prevent the infinite loop, if a query returns no useful peers, we
        // will cancel the recursiveness and wait for the heartbeat to trigger another query latter.
        // The heartbeat will attempt new discovery queries every N seconds if the node needs more
        // peers. As an optimization, this function can recursively trigger new discovery queries
        // immediatelly if we don't fulfill our peers needs after completing a query. This
        // recursiveness results in an infinite loop in networks where there not enough peers to
        // reach out target. To prevent the infinite loop, if a query returns no useful peers, we
        // will cancel the recursiveness and wait for the heartbeat to trigger another query latter.
        if results_count > 0 && to_dial_peers == 0 {
            debug!(self.log, "Skipping recursive discovery query after finding no useful results"; "results" => results_count);
            metrics::inc_counter(&crate::metrics::DISCOVERY_NO_USEFUL_ENRS);
        } else {
            // Queue another discovery if we need to
            self.maintain_peer_count(to_dial_peers, events)
        }
    }

    /// This function checks the status of our current peers and optionally requests a discovery
    /// query if we need to find more peers to maintain the current number of peers
    pub fn maintain_peer_count(
        &mut self,
        dialing_peers: usize,
        events: &mut SmallVec<[PeerManagerEvent; 16]>,
    ) {
        // Check if we need to do a discovery lookup
        if self.discovery_enabled {
            let peer_count = self.network_globals_provider.connected_or_dialing_peers();
            let outbound_only_peer_count = self
                .network_globals_provider
                .connected_outbound_only_peers();
            // return wanted number of peers
            let wanted_peers = if peer_count < self.target_peers.saturating_sub(dialing_peers) {
                // We need more peers in general.
                self.max_peers().saturating_sub(dialing_peers) - peer_count
            } else if outbound_only_peer_count < self.min_outbound_only_peers()
                && peer_count < self.max_outbound_dialing_peers()
            {
                self.max_outbound_dialing_peers()
                    .saturating_sub(dialing_peers)
                    .saturating_sub(peer_count)
            } else {
                0
            };
            if wanted_peers != 0 {
                // We need more peers, re-queue a discovery lookup.
                debug!(self.log, "Starting a new peer discovery query"; "connected" => peer_count, "target" => self.target_peers, "outbound" => outbound_only_peer_count, "wanted" => wanted_peers);
                events.push(PeerManagerEvent::DiscoverPeers(wanted_peers));
            }
        }
    }

    /// The target number of peers we would like to connect to.
    pub fn target_peers(&self) -> usize {
        self.target_peers
    }

    /// The maximum number of peers we allow to connect to us. This is `target_peers` * (1 +
    /// peer_excess_factor)
    pub fn max_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as usize
    }

    /// The maximum number of peers we allow when dialing a priority peer (i.e a peer that is
    /// subscribed to subnets that our validator requires. This is `target_peers` * (1 +
    /// PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)
    pub fn max_priority_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)).ceil()
            as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    pub fn min_outbound_only_peers(&self) -> usize {
        (self.target_peers as f32 * MIN_OUTBOUND_ONLY_FACTOR).ceil() as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    pub fn target_outbound_peers(&self) -> usize {
        (self.target_peers as f32 * MIN_OUTBOUND_ONLY_FACTOR).ceil() as usize
    }

    /// The maximum number of peers that are connected or dialing before we refuse to do another
    /// discovery search for more outbound peers. We can use up to half the priority peer excess allocation.
    pub fn max_outbound_dialing_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS / 2.0)).ceil()
            as usize
    }
}
