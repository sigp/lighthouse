///! This manages the discovery and management of peers.
mod enr_helpers;

use crate::metrics;
use crate::types::EnrBitfield;
use crate::Enr;
use crate::{error, NetworkConfig, NetworkGlobals, PeerInfo};
use enr_helpers::{BITFIELD_ENR_KEY, ETH2_ENR_KEY};
use futures::prelude::*;
use libp2p::core::{identity::Keypair, ConnectedPoint, Multiaddr, PeerId};
use libp2p::discv5::enr::NodeId;
use libp2p::discv5::{Discv5, Discv5Event};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction, PollParameters, ProtocolsHandler};
use slog::{debug, info, warn};
use ssz::{Decode, Encode};
use ssz_types::BitVector;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;
use types::{EnrForkId, EthSpec, SubnetId};

/// Maximum seconds before searching for extra peers.
const MAX_TIME_BETWEEN_PEER_SEARCHES: u64 = 120;
/// Initial delay between peer searches.
const INITIAL_SEARCH_DELAY: u64 = 5;
/// Local ENR storage filename.
const ENR_FILENAME: &str = "enr.dat";
/// Number of peers we'd like to have connected to a given long-lived subnet.
const TARGET_SUBNET_PEERS: u64 = 3;

/// Lighthouse discovery behaviour. This provides peer management and discovery using the Discv5
/// libp2p protocol.
pub struct Discovery<TSubstream, TSpec: EthSpec> {
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
    discovery: Discv5<TSubstream>,

    /// A collection of network constants that can be read from other threads.
    network_globals: Arc<NetworkGlobals<TSpec>>,

    /// Logger for the discovery behaviour.
    log: slog::Logger,
}

impl<TSubstream, TSpec: EthSpec> Discovery<TSubstream, TSpec> {
    pub fn new(
        local_key: &Keypair,
        config: &NetworkConfig,
        enr_fork_id: EnrForkId,
        network_globals: Arc<NetworkGlobals<TSpec>>,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        let log = log.clone();

        // checks if current ENR matches that found on disk
        let local_enr =
            enr_helpers::build_or_load_enr::<TSpec>(local_key.clone(), config, enr_fork_id, &log)?;

        *network_globals.local_enr.write() = Some(local_enr.clone());

        let enr_dir = match config.network_dir.to_str() {
            Some(path) => String::from(path),
            None => String::from(""),
        };

        info!(log, "ENR Initialised"; "enr" => local_enr.to_base64(), "seq" => local_enr.seq(), "id"=> format!("{}",local_enr.node_id()), "ip" => format!("{:?}", local_enr.ip()), "udp"=> format!("{:?}", local_enr.udp()), "tcp" => format!("{:?}", local_enr.tcp()));

        let listen_socket = SocketAddr::new(config.listen_address, config.discovery_port);

        let mut discovery = Discv5::new(
            local_enr,
            local_key.clone(),
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
                "peer_id" => format!("{}", bootnode_enr.peer_id())
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
            banned_peers: HashSet::new(),
            max_peers: config.max_peers,
            peer_discovery_delay: Delay::new(Instant::now()),
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

    /// Adds/Removes a subnet from the ENR Bitfield
    pub fn update_enr_bitfield(&mut self, subnet_id: SubnetId, value: bool) -> Result<(), String> {
        let id = *subnet_id as usize;

        let local_enr = self.discovery.local_enr();
        let bitfield_bytes = local_enr
            .get(BITFIELD_ENR_KEY)
            .ok_or_else(|| "ENR bitfield non-existent")?;

        let mut current_bitfield =
            BitVector::<TSpec::SubnetBitfieldLength>::from_ssz_bytes(bitfield_bytes)
                .map_err(|_| "Could not decode local ENR SSZ bitfield")?;

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
    }

    /// A request to find peers on a given subnet.
    // TODO: This logic should be improved with added sophistication in peer management
    // This currently checks for currently connected peers and if we don't have
    // PEERS_WANTED_BEFORE_DISCOVERY connected to a given subnet we search for more.
    pub fn peers_request(&mut self, subnet_id: SubnetId) {
        // TODO: Add PeerManager struct to do this loop for us

        let peers_on_subnet = self
            .network_globals
            .connected_peer_set
            .read()
            .values()
            .fold(0, |found_peers, peer_info| {
                if peer_info.on_subnet(subnet_id) {
                    found_peers + 1
                } else {
                    found_peers
                }
            });

        if peers_on_subnet < TARGET_SUBNET_PEERS {
            debug!(self.log, "Searching for peers for subnet";
                "subnet_id" => *subnet_id,
                "connected_peers_on_subnet" => peers_on_subnet,
                "target_subnet_peers" => TARGET_SUBNET_PEERS
            );
            // TODO: Update to predicate search
            self.find_peers();
        }
    }

    /* Internal Functions */

    /// Search for new peers using the underlying discovery mechanism.
    fn find_peers(&mut self) {
        // pick a random NodeId
        let random_node = NodeId::random();
        debug!(self.log, "Searching for peers");
        self.discovery.find_node(random_node);
    }
}

// Redirect all behaviour events to underlying discovery behaviour.
impl<TSubstream, TSpec: EthSpec> NetworkBehaviour for Discovery<TSubstream, TSpec>
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
        // Find ENR info about a peer if possible.
        let mut peer_info = PeerInfo::new();
        if let Some(enr) = self.discovery.enr_of_peer(&peer_id) {
            let bitfield = match enr.get(BITFIELD_ENR_KEY) {
                Some(bitfield_bytes) => {
                    match EnrBitfield::<TSpec>::from_ssz_bytes(bitfield_bytes) {
                        Ok(bitfield) => bitfield,
                        Err(e) => {
                            warn!(self.log, "Peer had invalid ENR bitfield"; 
                            "peer_id" => format!("{}", peer_id),
                            "error" => format!("{:?}", e));
                            return;
                        }
                    }
                }
                None => {
                    warn!(self.log, "Peer has no ENR bitfield"; 
                    "peer_id" => format!("{}", peer_id));
                    return;
                }
            };

            peer_info.enr_bitfield = Some(bitfield);
        }

        self.network_globals
            .connected_peer_set
            .write()
            .insert(peer_id, peer_info);
        // TODO: Drop peers if over max_peer limit

        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        metrics::set_gauge(
            &metrics::PEERS_CONNECTED,
            self.network_globals.connected_peers() as i64,
        );
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, _endpoint: ConnectedPoint) {
        self.network_globals
            .connected_peer_set
            .write()
            .remove(peer_id);

        metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
        metrics::set_gauge(
            &metrics::PEERS_CONNECTED,
            self.network_globals.connected_peers() as i64,
        );
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
        params: &mut impl PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        // search for peers if it is time
        loop {
            match self.peer_discovery_delay.poll() {
                Ok(Async::Ready(_)) => {
                    if self.network_globals.connected_peers() < self.max_peers {
                        self.find_peers();
                    }
                    // Set to maximum, and update to earlier, once we get our results back.
                    self.peer_discovery_delay.reset(
                        Instant::now() + Duration::from_secs(MAX_TIME_BETWEEN_PEER_SEARCHES),
                    );
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    warn!(self.log, "Discovery peer search failed"; "error" => format!("{:?}", e));
                }
            }
        }

        // Poll discovery
        loop {
            match self.discovery.poll(params) {
                Async::Ready(NetworkBehaviourAction::GenerateEvent(event)) => {
                    match event {
                        Discv5Event::Discovered(_enr) => {
                            // not concerned about FINDNODE results, rather the result of an entire
                            // query.
                        }
                        Discv5Event::SocketUpdated(socket) => {
                            info!(self.log, "Address updated"; "ip" => format!("{}",socket.ip()), "udp_port" => format!("{}", socket.port()));
                            metrics::inc_counter(&metrics::ADDRESS_UPDATE_COUNT);
                            let mut address = Multiaddr::from(socket.ip());
                            address.push(Protocol::Tcp(self.tcp_port));
                            let enr = self.discovery.local_enr();
                            enr_helpers::save_enr_to_disk(Path::new(&self.enr_dir), enr, &self.log);

                            return Async::Ready(NetworkBehaviourAction::ReportObservedAddr {
                                address,
                            });
                        }
                        Discv5Event::FindNodeResult { closer_peers, .. } => {
                            // TODO: Modify once ENR predicate search is available
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

                            if closer_peers.is_empty() {
                                debug!(self.log, "Discovery random query found no peers");
                            }
                            for peer_id in closer_peers {
                                // if we need more peers, attempt a connection

                                if self.network_globals.connected_peers() < self.max_peers
                                    && self
                                        .network_globals
                                        .connected_peer_set
                                        .read()
                                        .get(&peer_id)
                                        .is_none()
                                    && !self.banned_peers.contains(&peer_id)
                                {
                                    debug!(self.log, "Peer discovered"; "peer_id"=> format!("{:?}", peer_id));
                                    return Async::Ready(NetworkBehaviourAction::DialPeer {
                                        peer_id,
                                    });
                                }
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
