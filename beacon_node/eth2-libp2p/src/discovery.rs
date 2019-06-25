use crate::{error, NetworkConfig};
/// This manages the discovery and management of peers.
///
/// Currently using Kademlia for peer discovery.
///
use futures::prelude::*;
use libp2p::core::swarm::{
    ConnectedPoint, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::core::{identity::Keypair, Multiaddr, PeerId, ProtocolsHandler};
use libp2p::discv5::{Discv5, Discv5Event};
use libp2p::enr::{Enr, EnrBuilder, NodeId};
use libp2p::multiaddr::Protocol;
use slog::{debug, error, info, o, warn};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_timer::Delay;

/// Maximum seconds before searching for extra peers.
const MAX_TIME_BETWEEN_PEER_SEARCHES: u64 = 60;

/// Lighthouse discovery behaviour. This provides peer management and discovery using the Discv5
/// libp2p protocol.
pub struct Discovery<TSubstream> {
    /// The peers currently connected to libp2p streams.
    connected_peers: HashSet<PeerId>,

    /// The target number of connected peers on the libp2p interface.
    max_peers: usize,

    /// The delay between peer discovery searches.
    peer_discovery_delay: Delay,

    /// Tracks the last discovery delay. The delay is doubled each round until the max
    /// time is reached.
    past_discovery_delay: u64,

    /// The TCP port for libp2p. Used to convert an updated IP address to a multiaddr. Note: This
    /// assumes that the external TCP port is the same as the internal TCP port if behind a NAT.
    //TODO: Improve NAT handling limit the above restriction
    tcp_port: u16,

    /// The discovery behaviour used to discover new peers.
    discovery: Discv5<TSubstream>,

    /// Logger for the discovery behaviour.
    log: slog::Logger,
}

impl<TSubstream> Discovery<TSubstream> {
    pub fn new(
        local_key: &Keypair,
        net_conf: &NetworkConfig,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        let log = log.new(o!("Service" => "Libp2p-Discovery"));

        // Build the local ENR.
        // The first TCP listening address is used for the ENR record. This will inform our peers to
        // connect to this TCP port and establish libp2p streams.
        // Note: Discovery should update the ENR record's IP to the external IP as seen by the
        // majority of our peers.
        let tcp_multiaddr = net_conf
            .listen_addresses
            .iter()
            .filter(|a| {
                if let Some(Protocol::Tcp(_)) = a.iter().last() {
                    true
                } else {
                    false
                }
            })
            .next()
            .ok_or_else(|| "No valid TCP addresses")?;

        let ip: std::net::IpAddr = match tcp_multiaddr.iter().next() {
            Some(Protocol::Ip4(ip)) => ip.into(),
            Some(Protocol::Ip6(ip)) => ip.into(),
            _ => {
                error!(log, "Multiaddr has an invalid IP address");
                return Err(format!("Invalid IP Address: {}", tcp_multiaddr).into());
            }
        };

        let tcp_port = match tcp_multiaddr.iter().last() {
            Some(Protocol::Tcp(tcp)) => tcp,
            _ => unreachable!(),
        };

        let local_enr = EnrBuilder::new()
            .ip(ip.into())
            .tcp(tcp_port)
            .udp(net_conf.discovery_port)
            .build(&local_key)
            .map_err(|e| format!("Could not build Local ENR: {:?}", e))?;
        info!(log, "Local ENR: {}", local_enr.to_base64());

        let mut discovery = Discv5::new(local_enr, local_key.clone(), net_conf.discovery_address)
            .map_err(|e| format!("Discv5 service failed: {:?}", e))?;

        // Add bootnodes to routing table
        for bootnode_enr in net_conf.boot_nodes.clone() {
            discovery.add_enr(bootnode_enr);
        }

        Ok(Self {
            connected_peers: HashSet::new(),
            max_peers: net_conf.max_peers,
            peer_discovery_delay: Delay::new(Instant::now()),
            past_discovery_delay: 1,
            tcp_port,
            discovery,
            log,
        })
    }

    /// Manually search for peers. This restarts the discovery round, sparking multiple rapid
    /// queries.
    pub fn discover_peers(&mut self) {
        self.past_discovery_delay = 1;
        self.find_peers();
    }

    /// Add an Enr to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        self.discovery.add_enr(enr);
    }

    /// Search for new peers using the underlying discovery mechanism.
    fn find_peers(&mut self) {
        // pick a random NodeId
        let random_node = NodeId::random();
        debug!(self.log, "Searching for peers...");
        self.discovery.find_node(random_node);

        // update the time until next discovery
        let delay = {
            if self.past_discovery_delay < MAX_TIME_BETWEEN_PEER_SEARCHES {
                self.past_discovery_delay *= 2;
                self.past_discovery_delay
            } else {
                MAX_TIME_BETWEEN_PEER_SEARCHES
            }
        };
        self.peer_discovery_delay
            .reset(Instant::now() + Duration::from_secs(delay));
    }
}

// Redirect all behaviour events to underlying discovery behaviour.
impl<TSubstream> NetworkBehaviour for Discovery<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = <Discv5<TSubstream> as NetworkBehaviour>::ProtocolsHandler;
    type OutEvent = <Discv5<TSubstream> as NetworkBehaviour>::OutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        NetworkBehaviour::new_handler(&mut self.discovery)
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        // Let discovery track possible known peers.
        self.discovery.addresses_of_peer(peer_id)
    }

    fn inject_connected(&mut self, peer_id: PeerId, _endpoint: ConnectedPoint) {
        self.connected_peers.insert(peer_id);
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, _endpoint: ConnectedPoint) {
        self.connected_peers.remove(peer_id);
    }

    fn inject_replaced(
        &mut self,
        _peer_id: PeerId,
        _closed: ConnectedPoint,
        _opened: ConnectedPoint,
    ) {
        // discv5 doesn't implement
    }

    fn inject_node_event(
        &mut self,
        _peer_id: PeerId,
        _event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        // discv5 doesn't implement
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
        // search of peers if it is time
        loop {
            match self.peer_discovery_delay.poll() {
                Ok(Async::Ready(_)) => {
                    self.find_peers();
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    warn!(self.log, "Discovery peer search failed: {:?}", e);
                }
            }
        }

        // Poll discovery
        loop {
            match self.discovery.poll(params) {
                Async::Ready(NetworkBehaviourAction::GenerateEvent(event)) => {
                    match event {
                        Discv5Event::Discovered(enr) => {
                            debug!(self.log, "Discv5: Peer discovered"; "Peer"=> format!("{:?}", enr.peer_id()), "Addresses" => format!("{:?}", enr.multiaddr()));

                            let peer_id = enr.peer_id();
                            // if we need more peers, attempt a connection
                            if self.connected_peers.len() < self.max_peers
                                && self.connected_peers.get(&peer_id).is_none()
                            {
                                return Async::Ready(NetworkBehaviourAction::DialPeer { peer_id });
                            }
                        }
                        Discv5Event::SocketUpdated(socket) => {
                            info!(self.log, "Address updated"; "IP" => format!("{}",socket.ip()));
                            let mut address = Multiaddr::from(socket.ip());
                            address.push(Protocol::Tcp(self.tcp_port));
                            return Async::Ready(NetworkBehaviourAction::ReportObservedAddr {
                                address,
                            });
                        }
                        Discv5Event::FindNodeResult { closer_peers, .. } => {
                            debug!(self.log, "Discv5 query found {} peers", closer_peers.len());
                            if closer_peers.is_empty() {
                                debug!(self.log, "Discv5 random query yielded empty results");
                            }
                        }
                        _ => {}
                    }
                }
                // discv5 does not output any other NetworkBehaviourAction
                Async::Ready(_) => {}
                Async::NotReady => break,
            }
        }
        Async::NotReady
    }
}
