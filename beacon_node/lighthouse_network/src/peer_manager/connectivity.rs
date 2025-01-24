use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use discv5::Enr;
use types::EthSpec;
use crate::{EnrExt, NetworkGlobals, PeerConnectionStatus, PeerId};


pub trait NetworkGlobalsConnectivity {
    /// Returns the number of libp2p connected peers with outbound-only connections.
    fn connected_outbound_only_peers(&self) -> usize;

    /// Returns the number of libp2p peers that are either connected or being dialed.
    fn connected_or_dialing_peers(&self) -> usize;

    /// Update min ttl of a peer.
    fn update_min_ttl(&self, peer_id: &PeerId, min_ttl: Instant);

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    fn should_dial(&self, peer_id: &PeerId) -> bool;
}

pub struct LHNetworkGlobalsConnectivity<E: EthSpec> {
    /// Storage of network globals to access the `PeerDB`.
    network_globals: Arc<NetworkGlobals<E>>,
}

impl<E: EthSpec> LHNetworkGlobalsConnectivity<E> {
    pub fn new(network_globals: Arc<NetworkGlobals<E>>) -> Self {
        Self { network_globals }
    }

    /// Returns the number of libp2p connected peers with outbound-only connections.
    fn connected_outbound_only_peers(&self) -> usize {
        self.network_globals.connected_outbound_only_peers()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    fn connected_or_dialing_peers(&self) -> usize {
        self.network_globals.connected_or_dialing_peers()
    }

    /// Update min ttl of a peer.
    fn update_min_ttl(&self, peer_id: &PeerId, min_ttl: Instant) {
        self.network_globals.peers.write().update_min_ttl(peer_id, min_ttl);
    }

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    fn should_dial(&self, peer_id: &PeerId) -> bool {
        self.network_globals.peers.read().should_dial(peer_id)
    }
}

impl<E: EthSpec> NetworkGlobalsConnectivity for LHNetworkGlobalsConnectivity<E> {
    /// Returns the number of libp2p connected peers with outbound-only connections.
    fn connected_outbound_only_peers(&self) -> usize {
        self.connected_outbound_only_peers()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    fn connected_or_dialing_peers(&self) -> usize {
        self.connected_or_dialing_peers()
    }

    /// Update min ttl of a peer.
    fn update_min_ttl(&self, peer_id: &PeerId, min_ttl: Instant) {
        self.update_min_ttl(peer_id, min_ttl)
    }

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    fn should_dial(&self, peer_id: &PeerId) -> bool {
        self.should_dial(peer_id)
    }
}

pub struct Connectivity<N: NetworkGlobalsConnectivity> {
    target_peers: usize,
    peer_excess_factor: f32,
    priority_peer_excess: f32,
    min_outbound_only_factor: f32,
    target_outbound_only_factor: f32,
    /// Keeps track of whether the discovery service is enabled or not.
    discovery_enabled: bool,
    /// Peers queued to be dialed.
    peers_to_dial: Vec<Enr>,
    network_globals_connectivity: N
}

impl<N: NetworkGlobalsConnectivity> Connectivity<N> {
    pub fn new(
        target_peers: usize,
        peer_excess_factor: f32,
        priority_peer_excess: f32,
        min_outbound_only_factor: f32,
        target_outbound_only_factor: f32,
        discovery_enabled: bool,
        network_globals_connectivity: N,
    ) -> Self {
        Self {
            target_peers,
            peer_excess_factor,
            priority_peer_excess,
            min_outbound_only_factor,
            target_outbound_only_factor,
            discovery_enabled,
            peers_to_dial: Default::default(),
            network_globals_connectivity,
        }
    }

    /// A peer is being dialed.
    /// Returns true, if this peer will be dialed.
    pub fn dial_peer(&mut self, peer: Enr) -> bool{
        if self.network_globals_connectivity.should_dial(&peer.peer_id())
        {
            self.peers_to_dial.push(peer);
            true
        } else {
            false
        }
    }

    /// Peers that have been returned by discovery requests that are suitable for dialing are
    /// returned here.
    ///
    /// This function decides whether or not to dial these peers.
    pub fn peers_discovered(&mut self, results: &HashMap<Enr, Option<Instant>>) -> usize {

        let mut to_dial_peers = 0;
        let results_count = results.len();
        let connected_or_dialing = self.network_globals_connectivity.connected_or_dialing_peers();
        for (enr, min_ttl) in results {
            // There are two conditions in deciding whether to dial this peer.
            // 1. If we are less than our max connections. Discovery queries are executed to reach
            //    our target peers, so its fine to dial up to our max peers (which will get pruned
            //    in the next heartbeat down to our target).
            // 2. If the peer is one our validators require for a specific subnet, then it is
            //    considered a priority. We have pre-allocated some extra priority slots for these
            //    peers as specified by PRIORITY_PEER_EXCESS. Therefore we dial these peers, even
            //    if we are already at our max_peer limit.
            if !self.peers_to_dial.contains(&enr)
                && ((min_ttl.is_some()
                && connected_or_dialing + to_dial_peers < self.max_priority_peers())
                || connected_or_dialing + to_dial_peers < self.max_peers())
            {
                // This should be updated with the peer dialing. In fact created once the peer is
                // dialed
                let peer_id = enr.peer_id();
                if let Some(min_ttl) = min_ttl {
                    self.network_globals_connectivity.update_min_ttl(&peer_id, *min_ttl);
                }
                if self.dial_peer(enr.clone()) {
                    //debug!(self.log, "Added discovered ENR peer to dial queue"; "peer_id" => %peer_id);
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
        if results.len() > 0 && to_dial_peers == 0 {
            //debug!(self.log, "Skipping recursive discovery query after finding no useful results"; "results" => results_count);
            crate::metrics::inc_counter(&crate::metrics::DISCOVERY_NO_USEFUL_ENRS);
            0
        } else {
            // Queue another discovery if we need to
            self.maintain_peer_count(to_dial_peers)
        }
    }

    /// This function checks the status of our current peers and optionally requests a discovery
    /// query if we need to find more peers to maintain the current number of peers
    pub fn maintain_peer_count(&mut self, dialing_peers: usize) -> usize
        where N: NetworkGlobalsConnectivity {
        // Check if we need to do a discovery lookup
        if self.discovery_enabled {
            let peer_count = self.network_globals_connectivity.connected_or_dialing_peers();
            let outbound_only_peer_count = self.network_globals_connectivity.connected_outbound_only_peers();
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
            wanted_peers
        } else {
            0
        }
    }

    /// The maximum number of peers we allow to connect to us. This is `target_peers` * (1 +
    /// peer_excess_factor)
    pub fn max_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + self.peer_excess_factor)).ceil() as usize
    }

    /// The maximum number of peers we allow when dialing a priority peer (i.e a peer that is
    /// subscribed to subnets that our validator requires. This is `target_peers` * (1 +
    /// PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)
    pub fn max_priority_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + self.peer_excess_factor + self.priority_peer_excess)).ceil()
            as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    pub fn min_outbound_only_peers(&self) -> usize {
        (self.target_peers as f32 * self.min_outbound_only_factor).ceil() as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    pub fn target_outbound_peers(&self) -> usize {
        (self.target_peers as f32 * self.target_outbound_only_factor).ceil() as usize
    }

    /// The maximum number of peers that are connected or dialing before we refuse to do another
    /// discovery search for more outbound peers. We can use up to half the priority peer excess allocation.
    pub fn max_outbound_dialing_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + self.peer_excess_factor + self.priority_peer_excess / 2.0)).ceil()
            as usize
    }
}