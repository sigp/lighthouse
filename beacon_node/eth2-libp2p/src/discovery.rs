/// This manages the discovery and management of peers.
///
/// Currently using Kademlia for peer discovery.
///
use futures::prelude::*;
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::core::{Multiaddr, PeerId, ProtocolsHandler};
use libp2p::kad::{Kademlia, KademliaOut};
use slog::{debug, o, warn};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_timer::Delay;

//TODO: Make this dynamic
const TIME_BETWEEN_KAD_REQUESTS: Duration = Duration::from_secs(30);

/// Maintains a list of discovered peers and implements the discovery protocol to discover new
/// peers.
pub struct Discovery<TSubstream> {
    /// Queue of events to processed.
    // TODO: Re-implement as discovery protocol grows
    //    events: Vec<NetworkBehaviourAction<_, _>>,
    /// The discovery behaviour used to discover new peers.
    discovery: Kademlia<TSubstream>,
    /// The delay between peer discovery searches.
    peer_discovery_delay: Delay,
    /// Mapping of known addresses for peer ids.
    known_peers: HashMap<PeerId, Vec<Multiaddr>>,
    /// Logger for the discovery behaviour.
    log: slog::Logger,
}

impl<TSubstream> Discovery<TSubstream> {
    pub fn new(local_peer_id: PeerId, log: &slog::Logger) -> Self {
        let log = log.new(o!("Service" => "Libp2p-Discovery"));
        Self {
            //            events: Vec::new(),
            discovery: Kademlia::new(local_peer_id),
            peer_discovery_delay: Delay::new(Instant::now()),
            known_peers: HashMap::new(),
            log,
        }
    }

    /// Uses discovery to search for new peers.
    pub fn find_peers(&mut self) {
        // pick a random PeerId
        let random_peer = PeerId::random();
        debug!(self.log, "Searching for peers...");
        self.discovery.find_node(random_peer);

        // update the kademlia timeout
        self.peer_discovery_delay
            .reset(Instant::now() + TIME_BETWEEN_KAD_REQUESTS);
    }

    /// We have discovered an address for a peer, add it to known peers.
    pub fn add_connected_address(&mut self, peer_id: &PeerId, address: Multiaddr) {
        let known_peers = self
            .known_peers
            .entry(peer_id.clone())
            .or_insert_with(|| vec![]);
        if !known_peers.contains(&address) {
            known_peers.push(address.clone());
        }
        // pass the address on to kademlia
        self.discovery.add_connected_address(peer_id, address);
    }
}

// Redirect all behaviour event to underlying discovery behaviour.
impl<TSubstream> NetworkBehaviour for Discovery<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = <Kademlia<TSubstream> as NetworkBehaviour>::ProtocolsHandler;
    type OutEvent = <Kademlia<TSubstream> as NetworkBehaviour>::OutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NetworkBehaviour::new_handler(&mut self.discovery)
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        // Let discovery track possible known peers.
        self.discovery.addresses_of_peer(peer_id)
    }

    fn inject_connected(&mut self, peer_id: PeerId, endpoint: ConnectedPoint) {
        NetworkBehaviour::inject_connected(&mut self.discovery, peer_id, endpoint)
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, endpoint: ConnectedPoint) {
        NetworkBehaviour::inject_disconnected(&mut self.discovery, peer_id, endpoint)
    }

    fn inject_replaced(&mut self, peer_id: PeerId, closed: ConnectedPoint, opened: ConnectedPoint) {
        NetworkBehaviour::inject_replaced(&mut self.discovery, peer_id, closed, opened)
    }

    fn inject_node_event(
        &mut self,
        peer_id: PeerId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        // TODO: Upgrade to discv5
        NetworkBehaviour::inject_node_event(&mut self.discovery, peer_id, event)
    }

    fn poll(
        &mut self,
        params: &mut PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        // check to see if it's time to search for peers
        loop {
            match self.peer_discovery_delay.poll() {
                Ok(Async::Ready(_)) => {
                    self.find_peers();
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    warn!(
                        self.log,
                        "Error getting peers from discovery behaviour. Err: {:?}", e
                    );
                }
            }
        }
        // Poll discovery
        match self.discovery.poll(params) {
            Async::Ready(action) => {
                match &action {
                    NetworkBehaviourAction::GenerateEvent(disc_output) => match disc_output {
                        KademliaOut::Discovered {
                            peer_id, addresses, ..
                        } => {
                            debug!(self.log, "Kademlia peer discovered"; "Peer"=> format!("{:?}", peer_id), "Addresses" => format!("{:?}", addresses));
                        }
                        KademliaOut::FindNodeResult { closer_peers, .. } => {
                            debug!(
                                self.log,
                                "Kademlia query found {} peers",
                                closer_peers.len()
                            );
                            debug!(self.log, "Kademlia peers discovered"; "Peer"=> format!("{:?}", closer_peers));

                            if closer_peers.is_empty() {
                                debug!(self.log, "Kademlia random query yielded empty results");
                            }
                            return Async::Ready(action);
                        }
                        _ => {}
                    },
                    _ => {}
                };
                return Async::Ready(action);
            }
            Async::NotReady => (),
        }

        Async::NotReady
    }
}
