///! This manages the discovery and management of peers.
pub(crate) mod enr;
pub mod enr_ext;

// Allow external use of the lighthouse ENR builder
pub use enr::{build_enr, CombinedKey, Keypair};
pub use enr_ext::{CombinedKeyExt, EnrExt};

use crate::metrics;
use crate::{error, Enr, NetworkConfig, NetworkGlobals};
use discv5::{enr::NodeId, Discv5, Discv5Event};
use enr::{Eth2Enr, BITFIELD_ENR_KEY, ETH2_ENR_KEY};
use futures::prelude::*;
use libp2p::core::{connection::ConnectionId, Multiaddr, PeerId};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    protocols_handler::DummyProtocolsHandler, DialPeerCondition, NetworkBehaviour,
    NetworkBehaviourAction, PollParameters, ProtocolsHandler,
};
use lru::LruCache;
use slog::{crit, debug, info, warn};
use ssz::{Decode, Encode};
use ssz_types::BitVector;
use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{delay_until, Delay, Instant};
use types::{EnrForkId, EthSpec, SubnetId};

/// Maximum seconds before searching for extra peers.
const MAX_TIME_BETWEEN_PEER_SEARCHES: u64 = 120;
/// Initial delay between peer searches.
const INITIAL_SEARCH_DELAY: u64 = 5;
/// Local ENR storage filename.
pub const ENR_FILENAME: &str = "enr.dat";
/// Number of peers we'd like to have connected to a given long-lived subnet.
const TARGET_SUBNET_PEERS: u64 = 3;

/// Lighthouse discovery behaviour. This provides peer management and discovery using the Discv5
/// libp2p protocol.
pub struct Discovery<TSpec: EthSpec> {
    /// Events to be processed by the behaviour.
    events: VecDeque<NetworkBehaviourAction<void::Void, Discv5Event>>,

    /// A collection of seen live ENRs for quick lookup and to map peer-id's to ENRs.
    cached_enrs: LruCache<PeerId, Enr>,

    /// The currently banned peers.
    banned_peers: HashSet<PeerId>,

    /// The target number of connected peers on the libp2p interface.
    max_peers: usize,

    /// The directory where the ENR is stored.
    enr_dir: String,

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
    discovery: Discv5,

    /// A collection of network constants that can be read from other threads.
    network_globals: Arc<NetworkGlobals<TSpec>>,

    /// Logger for the discovery behaviour.
    log: slog::Logger,
}

impl<TSpec: EthSpec> Discovery<TSpec> {
    pub fn new(
        local_key: &Keypair,
        config: &NetworkConfig,
        network_globals: Arc<NetworkGlobals<TSpec>>,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        let log = log.clone();

        let enr_dir = match config.network_dir.to_str() {
            Some(path) => String::from(path),
            None => String::from(""),
        };

        let local_enr = network_globals.local_enr.read().clone();

        info!(log, "ENR Initialised"; "enr" => local_enr.to_base64(), "seq" => local_enr.seq(), "id"=> format!("{}",local_enr.node_id()), "ip" => format!("{:?}", local_enr.ip()), "udp"=> format!("{:?}", local_enr.udp()), "tcp" => format!("{:?}", local_enr.tcp()));

        let listen_socket = SocketAddr::new(config.listen_address, config.discovery_port);

        // convert the keypair into an ENR key
        let enr_key: CombinedKey = CombinedKey::from_libp2p(&local_key)?;

        let mut discovery = Discv5::new(
            local_enr,
            enr_key,
            config.discv5_config.clone(),
            listen_socket,
        )
        .map_err(|e| format!("Discv5 service failed. Error: {:?}", e))?;

        // Add bootnodes to routing table
        for bootnode_enr in config.boot_nodes.clone() {
            debug!(
                log,
                "Adding node to routing table";
                "node_id" => format!("{}", bootnode_enr.node_id()),
                "peer_id" => format!("{}", bootnode_enr.peer_id()),
                "ip" => format!("{:?}", bootnode_enr.ip()),
                "udp" => format!("{:?}", bootnode_enr.udp()),
                "tcp" => format!("{:?}", bootnode_enr.tcp())
            );
            let _ = discovery.add_enr(bootnode_enr).map_err(|e| {
                warn!(
                    log,
                    "Could not add peer to the local routing table";
                    "error" => format!("{}", e)
                )
            });
        }

        Ok(Self {
            events: VecDeque::with_capacity(16),
            cached_enrs: LruCache::new(50),
            banned_peers: HashSet::new(),
            max_peers: config.max_peers,
            peer_discovery_delay: delay_until(Instant::now()),
            past_discovery_delay: INITIAL_SEARCH_DELAY,
            tcp_port: config.libp2p_port,
            discovery,
            network_globals,
            log,
            enr_dir,
        })
    }

    /// Return the nodes local ENR.
    pub fn local_enr(&self) -> &Enr {
        self.discovery.local_enr()
    }

    /// Manually search for peers. This restarts the discovery round, sparking multiple rapid
    /// queries.
    pub fn discover_peers(&mut self) {
        self.past_discovery_delay = INITIAL_SEARCH_DELAY;
        self.find_peers();
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        // add the enr to seen caches
        self.cached_enrs.put(enr.peer_id(), enr.clone());

        let _ = self.discovery.add_enr(enr).map_err(|e| {
            warn!(
                self.log,
                "Could not add peer to the local routing table";
                "error" => format!("{}", e)
            )
        });
    }

    /// The peer has been banned. Add this peer to the banned list to prevent any future
    /// re-connections.
    // TODO: Remove the peer from the DHT if present
    pub fn peer_banned(&mut self, peer_id: PeerId) {
        self.banned_peers.insert(peer_id);
    }

    pub fn peer_unbanned(&mut self, peer_id: &PeerId) {
        self.banned_peers.remove(peer_id);
    }

    /// Returns an iterator over all enr entries in the DHT.
    pub fn enr_entries(&mut self) -> impl Iterator<Item = &Enr> {
        self.discovery.enr_entries()
    }

    /// Returns the ENR of a known peer if it exists.
    pub fn enr_of_peer(&mut self, peer_id: &PeerId) -> Option<Enr> {
        // first search the local cache
        if let Some(enr) = self.cached_enrs.get(peer_id) {
            return Some(enr.clone());
        }
        // not in the local cache, look in the routing table
        if let Ok(_node_id) = enr_ext::peer_id_to_node_id(peer_id) {
            // TODO: Need to update discv5
            //  self.discovery.find_enr(&node_id)
            return None;
        } else {
            return None;
        }
    }

    /// Adds/Removes a subnet from the ENR Bitfield
    pub fn update_enr_bitfield(&mut self, subnet_id: SubnetId, value: bool) -> Result<(), String> {
        let id = *subnet_id as usize;

        let local_enr = self.discovery.local_enr();
        let mut current_bitfield = local_enr.bitfield::<TSpec>()?;

        if id >= current_bitfield.len() {
            return Err(format!(
                "Subnet id: {} is outside the ENR bitfield length: {}",
                id,
                current_bitfield.len()
            ));
        }

        if current_bitfield
            .get(id)
            .map_err(|_| String::from("Subnet ID out of bounds"))?
            == value
        {
            return Err(format!(
                "Subnet id: {} already in the local ENR already has value: {}",
                id, value
            ));
        }

        // set the subnet bitfield in the ENR
        current_bitfield
            .set(id, value)
            .map_err(|_| String::from("Subnet ID out of bounds, could not set subnet ID"))?;

        // insert the bitfield into the ENR record
        let _ = self
            .discovery
            .enr_insert(BITFIELD_ENR_KEY, current_bitfield.as_ssz_bytes());

        // replace the global version
        *self.network_globals.local_enr.write() = self.discovery.local_enr().clone();
        Ok(())
    }

    /// Updates the `eth2` field of our local ENR.
    pub fn update_eth2_enr(&mut self, enr_fork_id: EnrForkId) {
        // to avoid having a reference to the spec constant, for the logging we assume
        // FAR_FUTURE_EPOCH is u64::max_value()
        let next_fork_epoch_log = if enr_fork_id.next_fork_epoch == u64::max_value() {
            String::from("No other fork")
        } else {
            format!("{:?}", enr_fork_id.next_fork_epoch)
        };

        info!(self.log, "Updating the ENR fork version";
            "fork_digest" => format!("{:?}", enr_fork_id.fork_digest),
            "next_fork_version" => format!("{:?}", enr_fork_id.next_fork_version),
            "next_fork_epoch" => next_fork_epoch_log,
        );

        let _ = self
            .discovery
            .enr_insert(ETH2_ENR_KEY.into(), enr_fork_id.as_ssz_bytes())
            .map_err(|e| {
                warn!(
                    self.log,
                    "Could not update eth2 ENR field";
                    "error" => format!("{:?}", e)
                )
            });

        // replace the global version with discovery version
        *self.network_globals.local_enr.write() = self.discovery.local_enr().clone();
    }

    /// A request to find peers on a given subnet.
    // TODO: This logic should be improved with added sophistication in peer management
    // This currently checks for currently connected peers and if we don't have
    // PEERS_WANTED_BEFORE_DISCOVERY connected to a given subnet we search for more.
    pub fn peers_request(&mut self, subnet_id: SubnetId) {
        let peers_on_subnet = self
            .network_globals
            .peers
            .read()
            .peers_on_subnet(subnet_id)
            .count() as u64;

        if peers_on_subnet < TARGET_SUBNET_PEERS {
            let target_peers = TARGET_SUBNET_PEERS - peers_on_subnet;
            debug!(self.log, "Searching for peers for subnet";
                "subnet_id" => *subnet_id,
                "connected_peers_on_subnet" => peers_on_subnet,
                "target_subnet_peers" => TARGET_SUBNET_PEERS,
                "peers_to_find" => target_peers
            );

            let log_clone = self.log.clone();

            let subnet_predicate = move |enr: &Enr| {
                if let Some(bitfield_bytes) = enr.get(BITFIELD_ENR_KEY) {
                    let bitfield = match BitVector::<TSpec::SubnetBitfieldLength>::from_ssz_bytes(
                        bitfield_bytes,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(log_clone, "Could not decode ENR bitfield for peer"; "peer_id" => format!("{}", enr.peer_id()), "error" => format!("{:?}", e));
                            return false;
                        }
                    };

                    return bitfield.get(*subnet_id as usize).unwrap_or_else(|_| {
                        debug!(log_clone, "Peer found but not on desired subnet"; "peer_id" => format!("{}", enr.peer_id()));
                        false
                    });
                }
                false
            };

            // start the query
            self.start_query(subnet_predicate, target_peers as usize);
        } else {
            debug!(self.log, "Discovery ignored";
                "reason" => "Already connected to desired peers",
                "connected_peers_on_subnet" => peers_on_subnet,
                "target_subnet_peers" => TARGET_SUBNET_PEERS,
            );
        }
    }

    /* Internal Functions */

    /// Run a standard query to search for more peers.
    ///
    /// This searches for the standard kademlia bucket size (16) peers.
    fn find_peers(&mut self) {
        debug!(self.log, "Searching for peers");
        self.start_query(|_| true, 16);
    }

    /// Search for a specified number of new peers using the underlying discovery mechanism.
    ///
    /// This can optionally search for peers for a given predicate. Regardless of the predicate
    /// given, this will only search for peers on the same enr_fork_id as specified in the local
    /// ENR.
    fn start_query<F>(&mut self, enr_predicate: F, num_nodes: usize)
    where
        F: Fn(&Enr) -> bool + Send + 'static + Clone,
    {
        // pick a random NodeId
        let random_node = NodeId::random();

        let enr_fork_id = match self.local_enr().eth2() {
            Ok(v) => v,
            Err(e) => {
                crit!(self.log, "Local ENR has no fork id"; "error" => e);
                return;
            }
        };
        // predicate for finding nodes with a matching fork
        let eth2_fork_predicate = move |enr: &Enr| enr.eth2() == Ok(enr_fork_id.clone());
        let predicate = move |enr: &Enr| eth2_fork_predicate(enr) && enr_predicate(enr);

        // general predicate
        self.discovery
            .find_enr_predicate(random_node, predicate, num_nodes);
    }
}

// Build a dummy Network behaviour around the discv5 server
impl<TSpec: EthSpec> NetworkBehaviour for Discovery<TSpec> {
    type ProtocolsHandler = DummyProtocolsHandler;
    type OutEvent = Discv5Event;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DummyProtocolsHandler::default()
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        if let Some(enr) = self.enr_of_peer(peer_id) {
            // ENR's may have multiple Multiaddrs. The multi-addr associated with the UDP
            // port is removed, which is assumed to be associated with the discv5 protocol (and
            // therefore irrelevant for other libp2p components).
            let mut out_list = enr.multiaddr();
            out_list.retain(|addr| {
                addr.iter()
                    .find(|v| match v {
                        Protocol::Udp(_) => true,
                        _ => false,
                    })
                    .is_none()
            });

            out_list
        } else {
            // PeerId is not known
            Vec::new()
        }
    }

    // ignore libp2p connections/streams
    fn inject_connected(&mut self, _: &PeerId) {}

    // ignore libp2p connections/streams
    fn inject_disconnected(&mut self, _: &PeerId) {}

    // no libp2p discv5 events - event originate from the session_service.
    fn inject_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        _event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        void::unreachable(_event)
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        // search for peers if it is time
        loop {
            match self.peer_discovery_delay.poll_unpin(cx) {
                Poll::Ready(_) => {
                    if self.network_globals.connected_peers() < self.max_peers {
                        self.find_peers();
                    }
                    // Set to maximum, and update to earlier, once we get our results back.
                    self.peer_discovery_delay.reset(
                        Instant::now() + Duration::from_secs(MAX_TIME_BETWEEN_PEER_SEARCHES),
                    );
                }
                Poll::Pending => break,
            }
        }

        // Poll discovery
        loop {
            match self.discovery.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    match event {
                        Discv5Event::Discovered(_enr) => {
                            // peers that get discovered during a query but are not contactable or
                            // don't match a predicate can end up here. For debugging purposes we
                            // log these to see if we are unnecessarily dropping discovered peers
                            /*
                            if enr.eth2() == self.local_enr().eth2() {
                                trace!(self.log, "Peer found in process of query"; "peer_id" => format!("{}", enr.peer_id()), "tcp_socket" => enr.tcp_socket());
                            } else {
                                // this is temporary warning for debugging the DHT
                                warn!(self.log, "Found peer during discovery not on correct fork"; "peer_id" => format!("{}", enr.peer_id()), "tcp_socket" => enr.tcp_socket());
                            }
                            */
                        }
                        Discv5Event::SocketUpdated(socket) => {
                            info!(self.log, "Address updated"; "ip" => format!("{}",socket.ip()), "udp_port" => format!("{}", socket.port()));
                            metrics::inc_counter(&metrics::ADDRESS_UPDATE_COUNT);
                            let mut address = Multiaddr::from(socket.ip());
                            address.push(Protocol::Tcp(self.tcp_port));
                            let enr = self.discovery.local_enr();
                            enr::save_enr_to_disk(Path::new(&self.enr_dir), enr, &self.log);

                            return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr {
                                address,
                            });
                        }
                        Discv5Event::FindNodeResult { closer_peers, .. } => {
                            debug!(self.log, "Discovery query completed"; "peers_found" => closer_peers.len());
                            // update the time to the next query
                            if self.past_discovery_delay < MAX_TIME_BETWEEN_PEER_SEARCHES {
                                self.past_discovery_delay *= 2;
                            }
                            let delay = std::cmp::max(
                                self.past_discovery_delay,
                                MAX_TIME_BETWEEN_PEER_SEARCHES,
                            );
                            self.peer_discovery_delay
                                .reset(Instant::now() + Duration::from_secs(delay));

                            for enr in closer_peers {
                                // cache known peers
                                let peer_id = enr.peer_id();
                                self.cached_enrs.put(enr.peer_id(), enr);

                                // if we need more peers, attempt a connection
                                if self.network_globals.connected_or_dialing_peers()
                                    < self.max_peers
                                    && !self
                                        .network_globals
                                        .peers
                                        .read()
                                        .is_connected_or_dialing(&peer_id)
                                    && !self.banned_peers.contains(&peer_id)
                                {
                                    // TODO: Debugging only
                                    // NOTE: The peer manager will get updated by the global swarm.
                                    let connection_status = self
                                        .network_globals
                                        .peers
                                        .read()
                                        .connection_status(&peer_id);
                                    debug!(self.log, "Connecting to discovered peer"; "peer_id"=> peer_id.to_string(), "status" => format!("{:?}", connection_status));
                                    self.events.push_back(NetworkBehaviourAction::DialPeer {
                                        peer_id,
                                        condition: DialPeerCondition::Disconnected,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // discv5 does not output any other NetworkBehaviourAction
                Poll::Ready(_) => {}
                Poll::Pending => break,
            }
        }

        // process any queued events
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
