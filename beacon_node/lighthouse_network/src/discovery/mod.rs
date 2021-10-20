//! The discovery sub-behaviour of Lighthouse.
//!
//! This module creates a libp2p dummy-behaviour built around the discv5 protocol. It handles
//! queries and manages access to the discovery routing table.

pub(crate) mod enr;
pub mod enr_ext;

// Allow external use of the lighthouse ENR builder
use crate::{config, metrics};
use crate::{error, Enr, NetworkConfig, NetworkGlobals, Subnet, SubnetDiscovery};
use discv5::{enr::NodeId, Discv5, Discv5Event};
pub use enr::{
    build_enr, create_enr_builder_from_config, load_enr_from_disk, use_or_load_enr, CombinedKey,
    Eth2Enr,
};
pub use enr_ext::{peer_id_to_node_id, CombinedKeyExt, EnrExt};
pub use libp2p::core::identity::{Keypair, PublicKey};

use enr::{ATTESTATION_BITFIELD_ENR_KEY, ETH2_ENR_KEY, SYNC_COMMITTEE_BITFIELD_ENR_KEY};
use futures::prelude::*;
use futures::stream::FuturesUnordered;
pub use libp2p::{
    core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId},
    swarm::{
        protocols_handler::ProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction as NBAction,
        NotifyHandler, PollParameters, SubstreamProtocol,
    },
};
use lru::LruCache;
use slog::{crit, debug, error, info, trace, warn};
use ssz::Encode;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use types::{EnrForkId, EthSpec};

mod subnet_predicate;
pub use subnet_predicate::subnet_predicate;

/// Local ENR storage filename.
pub const ENR_FILENAME: &str = "enr.dat";
/// Target number of peers we'd like to have connected to a given long-lived subnet.
pub const TARGET_SUBNET_PEERS: usize = config::MESH_N_LOW;
/// Target number of peers to search for given a grouped subnet query.
const TARGET_PEERS_FOR_GROUPED_QUERY: usize = 6;
/// Number of times to attempt a discovery request.
const MAX_DISCOVERY_RETRY: usize = 3;
/// The maximum number of concurrent subnet discovery queries.
/// Note: we always allow a single FindPeers query, so we would be
/// running a maximum of `MAX_CONCURRENT_SUBNET_QUERIES + 1`
/// discovery queries at a time.
const MAX_CONCURRENT_SUBNET_QUERIES: usize = 2;
/// The max number of subnets to search for in a single subnet discovery query.
const MAX_SUBNETS_IN_QUERY: usize = 3;
/// The number of closest peers to search for when doing a regular peer search.
///
/// We could reduce this constant to speed up queries however at the cost of security. It will
/// make it easier to peers to eclipse this node. Kademlia suggests a value of 16.
const FIND_NODE_QUERY_CLOSEST_PEERS: usize = 16;
/// The threshold for updating `min_ttl` on a connected peer.
const DURATION_DIFFERENCE: Duration = Duration::from_millis(1);

/// The events emitted by polling discovery.
pub enum DiscoveryEvent {
    /// A query has completed. This result contains a mapping of discovered peer IDs to the `min_ttl`
    /// of the peer if it is specified.
    QueryResult(HashMap<PeerId, Option<Instant>>),
    /// This indicates that our local UDP socketaddr has been updated and we should inform libp2p.
    SocketUpdated(SocketAddr),
}

#[derive(Clone, PartialEq)]
struct SubnetQuery {
    subnet: Subnet,
    min_ttl: Option<Instant>,
    retries: usize,
}

impl SubnetQuery {
    /// Returns true if this query has expired.
    pub fn expired(&self) -> bool {
        if let Some(ttl) = self.min_ttl {
            ttl < Instant::now()
        }
        // `None` corresponds to long lived subnet discovery requests.
        else {
            false
        }
    }
}

impl std::fmt::Debug for SubnetQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let min_ttl_secs = self
            .min_ttl
            .map(|ttl| ttl.saturating_duration_since(Instant::now()).as_secs());
        f.debug_struct("SubnetQuery")
            .field("subnet", &self.subnet)
            .field("min_ttl_secs", &min_ttl_secs)
            .field("retries", &self.retries)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum QueryType {
    /// We are searching for subnet peers.
    Subnet(Vec<SubnetQuery>),
    /// We are searching for more peers without ENR or time constraints.
    FindPeers,
}

/// The result of a query.
struct QueryResult {
    query_type: QueryType,
    result: Result<Vec<Enr>, discv5::QueryError>,
}

// Awaiting the event stream future
enum EventStream {
    /// Awaiting an event stream to be generated. This is required due to the poll nature of
    /// `Discovery`
    Awaiting(
        Pin<
            Box<
                dyn Future<Output = Result<mpsc::Receiver<Discv5Event>, discv5::Discv5Error>>
                    + Send,
            >,
        >,
    ),
    /// The future has completed.
    Present(mpsc::Receiver<Discv5Event>),
    // The future has failed or discv5 has been disabled. There are no events from discv5.
    InActive,
}

/// The main discovery service. This can be disabled via CLI arguements. When disabled the
/// underlying processes are not started, but this struct still maintains our current ENR.
pub struct Discovery<TSpec: EthSpec> {
    /// A collection of seen live ENRs for quick lookup and to map peer-id's to ENRs.
    cached_enrs: LruCache<PeerId, Enr>,

    /// The directory where the ENR is stored.
    enr_dir: String,

    /// The handle for the underlying discv5 Server.
    ///
    /// This is behind a Reference counter to allow for futures to be spawned and polled with a
    /// static lifetime.
    discv5: Discv5,

    /// A collection of network constants that can be read from other threads.
    network_globals: Arc<NetworkGlobals<TSpec>>,

    /// Indicates if we are actively searching for peers. We only allow a single FindPeers query at
    /// a time, regardless of the query concurrency.
    find_peer_active: bool,

    /// A queue of subnet queries to be processed.
    queued_queries: VecDeque<SubnetQuery>,

    /// Active discovery queries.
    active_queries: FuturesUnordered<std::pin::Pin<Box<dyn Future<Output = QueryResult> + Send>>>,

    /// The discv5 event stream.
    event_stream: EventStream,

    /// Indicates if the discovery service has been started. When the service is disabled, this is
    /// always false.
    pub started: bool,

    /// Logger for the discovery behaviour.
    log: slog::Logger,
}

impl<TSpec: EthSpec> Discovery<TSpec> {
    /// NOTE: Creating discovery requires running within a tokio execution environment.
    pub async fn new(
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

        info!(log, "ENR Initialised"; "enr" => local_enr.to_base64(), "seq" => local_enr.seq(), "id"=> %local_enr.node_id(), "ip" => ?local_enr.ip(), "udp"=> ?local_enr.udp(), "tcp" => ?local_enr.tcp());

        let listen_socket = SocketAddr::new(config.listen_address, config.discovery_port);

        // convert the keypair into an ENR key
        let enr_key: CombinedKey = CombinedKey::from_libp2p(local_key)?;

        let mut discv5 = Discv5::new(local_enr, enr_key, config.discv5_config.clone())
            .map_err(|e| format!("Discv5 service failed. Error: {:?}", e))?;

        // Add bootnodes to routing table
        for bootnode_enr in config.boot_nodes_enr.clone() {
            debug!(
                log,
                "Adding node to routing table";
                "node_id" => %bootnode_enr.node_id(),
                "peer_id" => %bootnode_enr.peer_id(),
                "ip" => ?bootnode_enr.ip(),
                "udp" => ?bootnode_enr.udp(),
                "tcp" => ?bootnode_enr.tcp()
            );
            let repr = bootnode_enr.to_string();
            let _ = discv5.add_enr(bootnode_enr).map_err(|e| {
                error!(
                    log,
                    "Could not add peer to the local routing table";
                    "addr" => repr,
                    "error" => e.to_string(),
                )
            });
        }

        // Start the discv5 service and obtain an event stream
        let event_stream = if !config.disable_discovery {
            discv5
                .start(listen_socket)
                .map_err(|e| e.to_string())
                .await?;
            debug!(log, "Discovery service started");
            EventStream::Awaiting(Box::pin(discv5.event_stream()))
        } else {
            EventStream::InActive
        };

        if !config.boot_nodes_multiaddr.is_empty() {
            info!(log, "Contacting Multiaddr boot-nodes for their ENR");
        }

        // get futures for requesting the Enrs associated to these multiaddr and wait for their
        // completion
        let mut fut_coll = config
            .boot_nodes_multiaddr
            .iter()
            .map(|addr| addr.to_string())
            // request the ENR for this multiaddr and keep the original for logging
            .map(|addr| {
                futures::future::join(
                    discv5.request_enr(addr.clone()),
                    futures::future::ready(addr),
                )
            })
            .collect::<FuturesUnordered<_>>();

        while let Some((result, original_addr)) = fut_coll.next().await {
            match result {
                Ok(enr) => {
                    debug!(
                        log,
                        "Adding node to routing table";
                        "node_id" => %enr.node_id(),
                        "peer_id" => %enr.peer_id(),
                        "ip" => ?enr.ip(),
                        "udp" => ?enr.udp(),
                        "tcp" => ?enr.tcp()
                    );
                    let _ = discv5.add_enr(enr).map_err(|e| {
                        error!(
                            log,
                            "Could not add peer to the local routing table";
                            "addr" => original_addr.to_string(),
                            "error" => e.to_string(),
                        )
                    });
                }
                Err(e) => {
                    error!(log, "Error getting mapping to ENR"; "multiaddr" => original_addr.to_string(), "error" => e.to_string())
                }
            }
        }

        Ok(Self {
            cached_enrs: LruCache::new(50),
            network_globals,
            find_peer_active: false,
            queued_queries: VecDeque::with_capacity(10),
            active_queries: FuturesUnordered::new(),
            discv5,
            event_stream,
            started: !config.disable_discovery,
            log,
            enr_dir,
        })
    }

    /// Return the nodes local ENR.
    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Return the cached enrs.
    pub fn cached_enrs(&self) -> impl Iterator<Item = (&PeerId, &Enr)> {
        self.cached_enrs.iter()
    }

    /// Removes a cached ENR from the list.
    pub fn remove_cached_enr(&mut self, peer_id: &PeerId) -> Option<Enr> {
        self.cached_enrs.pop(peer_id)
    }

    /// This adds a new `FindPeers` query to the queue if one doesn't already exist.
    pub fn discover_peers(&mut self) {
        // If the discv5 service isn't running or we are in the process of a query, don't bother queuing a new one.
        if !self.started || self.find_peer_active {
            return;
        }
        // Immediately start a FindNode query
        debug!(self.log, "Starting a peer discovery request");
        self.find_peer_active = true;
        self.start_query(QueryType::FindPeers, FIND_NODE_QUERY_CLOSEST_PEERS, |_| {
            true
        });
    }

    /// Processes a request to search for more peers on a subnet.
    pub fn discover_subnet_peers(&mut self, subnets_to_discover: Vec<SubnetDiscovery>) {
        // If the discv5 service isn't running, ignore queries
        if !self.started {
            return;
        }
        trace!(
            self.log,
            "Starting discovery query for subnets";
            "subnets" => ?subnets_to_discover.iter().map(|s| s.subnet).collect::<Vec<_>>()
        );
        for subnet in subnets_to_discover {
            self.add_subnet_query(subnet.subnet, subnet.min_ttl, 0);
        }
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        // add the enr to seen caches
        self.cached_enrs.put(enr.peer_id(), enr.clone());

        if let Err(e) = self.discv5.add_enr(enr) {
            debug!(
                self.log,
                "Could not add peer to the local routing table";
                "error" => %e
            )
        }
    }

    /// Returns an iterator over all enr entries in the DHT.
    pub fn table_entries_enr(&mut self) -> Vec<Enr> {
        self.discv5.table_entries_enr()
    }

    /// Returns the ENR of a known peer if it exists.
    pub fn enr_of_peer(&mut self, peer_id: &PeerId) -> Option<Enr> {
        // first search the local cache
        if let Some(enr) = self.cached_enrs.get(peer_id) {
            return Some(enr.clone());
        }
        // not in the local cache, look in the routing table
        if let Ok(node_id) = enr_ext::peer_id_to_node_id(peer_id) {
            self.discv5.find_enr(&node_id)
        } else {
            None
        }
    }

    /// Updates the local ENR TCP port.
    /// There currently isn't a case to update the address here. We opt for discovery to
    /// automatically update the external address.
    ///
    /// If the external address needs to be modified, use `update_enr_udp_socket.
    pub fn update_enr_tcp_port(&mut self, port: u16) -> Result<(), String> {
        self.discv5
            .enr_insert("tcp", &port.to_be_bytes())
            .map_err(|e| format!("{:?}", e))?;

        // replace the global version
        *self.network_globals.local_enr.write() = self.discv5.local_enr();
        // persist modified enr to disk
        enr::save_enr_to_disk(Path::new(&self.enr_dir), &self.local_enr(), &self.log);
        Ok(())
    }

    /// Updates the local ENR UDP socket.
    ///
    /// This is with caution. Discovery should automatically maintain this. This should only be
    /// used when automatic discovery is disabled.
    pub fn update_enr_udp_socket(&mut self, socket_addr: SocketAddr) -> Result<(), String> {
        match socket_addr {
            SocketAddr::V4(socket) => {
                self.discv5
                    .enr_insert("ip", &socket.ip().octets())
                    .map_err(|e| format!("{:?}", e))?;
                self.discv5
                    .enr_insert("udp", &socket.port().to_be_bytes())
                    .map_err(|e| format!("{:?}", e))?;
            }
            SocketAddr::V6(socket) => {
                self.discv5
                    .enr_insert("ip6", &socket.ip().octets())
                    .map_err(|e| format!("{:?}", e))?;
                self.discv5
                    .enr_insert("udp6", &socket.port().to_be_bytes())
                    .map_err(|e| format!("{:?}", e))?;
            }
        }

        // replace the global version
        *self.network_globals.local_enr.write() = self.discv5.local_enr();
        // persist modified enr to disk
        enr::save_enr_to_disk(Path::new(&self.enr_dir), &self.local_enr(), &self.log);
        Ok(())
    }

    /// Adds/Removes a subnet from the ENR attnets/syncnets Bitfield
    pub fn update_enr_bitfield(&mut self, subnet: Subnet, value: bool) -> Result<(), String> {
        let local_enr = self.discv5.local_enr();

        match subnet {
            Subnet::Attestation(id) => {
                let id = *id as usize;
                let mut current_bitfield = local_enr.attestation_bitfield::<TSpec>()?;
                if id >= current_bitfield.len() {
                    return Err(format!(
                        "Subnet id: {} is outside the ENR bitfield length: {}",
                        id,
                        current_bitfield.len()
                    ));
                }

                // The bitfield is already set to required value
                if current_bitfield
                    .get(id)
                    .map_err(|_| String::from("Subnet ID out of bounds"))?
                    == value
                {
                    return Ok(());
                }

                // set the subnet bitfield in the ENR
                current_bitfield.set(id, value).map_err(|_| {
                    String::from("Subnet ID out of bounds, could not set subnet ID")
                })?;

                // insert the bitfield into the ENR record
                self.discv5
                    .enr_insert(
                        ATTESTATION_BITFIELD_ENR_KEY,
                        &current_bitfield.as_ssz_bytes(),
                    )
                    .map_err(|e| format!("{:?}", e))?;
            }
            Subnet::SyncCommittee(id) => {
                let id = *id as usize;
                let mut current_bitfield = local_enr.sync_committee_bitfield::<TSpec>()?;

                if id >= current_bitfield.len() {
                    return Err(format!(
                        "Subnet id: {} is outside the ENR bitfield length: {}",
                        id,
                        current_bitfield.len()
                    ));
                }

                // The bitfield is already set to required value
                if current_bitfield
                    .get(id)
                    .map_err(|_| String::from("Subnet ID out of bounds"))?
                    == value
                {
                    return Ok(());
                }

                // set the subnet bitfield in the ENR
                current_bitfield.set(id, value).map_err(|_| {
                    String::from("Subnet ID out of bounds, could not set subnet ID")
                })?;

                // insert the bitfield into the ENR record
                self.discv5
                    .enr_insert(
                        SYNC_COMMITTEE_BITFIELD_ENR_KEY,
                        &current_bitfield.as_ssz_bytes(),
                    )
                    .map_err(|e| format!("{:?}", e))?;
            }
        }

        // replace the global version
        *self.network_globals.local_enr.write() = self.discv5.local_enr();

        // persist modified enr to disk
        enr::save_enr_to_disk(Path::new(&self.enr_dir), &self.local_enr(), &self.log);
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
            "fork_digest" => ?enr_fork_id.fork_digest,
            "next_fork_version" => ?enr_fork_id.next_fork_version,
            "next_fork_epoch" => next_fork_epoch_log,
        );

        let _ = self
            .discv5
            .enr_insert(ETH2_ENR_KEY, &enr_fork_id.as_ssz_bytes())
            .map_err(|e| {
                warn!(
                    self.log,
                    "Could not update eth2 ENR field";
                    "error" => ?e
                )
            });

        // replace the global version with discovery version
        *self.network_globals.local_enr.write() = self.discv5.local_enr();

        // persist modified enr to disk
        enr::save_enr_to_disk(Path::new(&self.enr_dir), &self.local_enr(), &self.log);
    }

    // Bans a peer and it's associated seen IP addresses.
    pub fn ban_peer(&mut self, peer_id: &PeerId, ip_addresses: Vec<IpAddr>) {
        // first try and convert the peer_id to a node_id.
        if let Ok(node_id) = peer_id_to_node_id(peer_id) {
            // If we could convert this peer id, remove it from the DHT and ban it from discovery.
            self.discv5.ban_node(&node_id, None);
            // Remove the node from the routing table.
            self.discv5.remove_node(&node_id);
        }

        for ip_address in ip_addresses {
            self.discv5.ban_ip(ip_address, None);
        }
    }

    /// Unbans the peer in discovery.
    pub fn unban_peer(&mut self, peer_id: &PeerId, ip_addresses: Vec<IpAddr>) {
        // first try and convert the peer_id to a node_id.
        if let Ok(node_id) = peer_id_to_node_id(peer_id) {
            // If we could convert this peer id, remove it from the DHT and ban it from discovery.
            self.discv5.ban_node_remove(&node_id);
        }

        for ip_address in ip_addresses {
            self.discv5.ban_ip_remove(&ip_address);
        }
    }

    ///  Marks node as disconnected in the DHT, freeing up space for other nodes, this also removes
    ///  nodes from the cached ENR list.
    pub fn disconnect_peer(&mut self, peer_id: &PeerId) {
        if let Ok(node_id) = peer_id_to_node_id(peer_id) {
            self.discv5.disconnect_node(&node_id);
        }
        // Remove the peer from the cached list, to prevent redialing disconnected
        // peers.
        self.cached_enrs.pop(peer_id);
    }

    /* Internal Functions */

    /// Adds a subnet query if one doesn't exist. If a subnet query already exists, this
    /// updates the min_ttl field.
    fn add_subnet_query(&mut self, subnet: Subnet, min_ttl: Option<Instant>, retries: usize) {
        // remove the entry and complete the query if greater than the maximum search count
        if retries > MAX_DISCOVERY_RETRY {
            debug!(
                self.log,
                "Subnet peer discovery did not find sufficient peers. Reached max retry limit"
            );
            return;
        }

        // Search through any queued requests and update the timeout if a query for this subnet
        // already exists
        let mut found = false;
        for subnet_query in self.queued_queries.iter_mut() {
            if subnet_query.subnet == subnet {
                if subnet_query.min_ttl < min_ttl {
                    subnet_query.min_ttl = min_ttl;
                }
                // update the number of retries
                subnet_query.retries = retries;
                // mimic an `Iter::Find()` and short-circuit the loop
                found = true;
                break;
            }
        }
        if !found {
            // update the metrics and insert into the queue.
            trace!(self.log, "Queuing subnet query"; "subnet" => ?subnet, "retries" => retries);
            self.queued_queries.push_back(SubnetQuery {
                subnet,
                min_ttl,
                retries,
            });
            metrics::set_gauge(&metrics::DISCOVERY_QUEUE, self.queued_queries.len() as i64);
        }
    }

    /// Consume the discovery queue and initiate queries when applicable.
    ///
    /// This also sanitizes the queue removing out-dated queries.
    /// Returns `true` if any of the queued queries is processed and a subnet discovery
    /// query is started.
    fn process_queue(&mut self) -> bool {
        // Sanitize the queue, removing any out-dated subnet queries
        self.queued_queries.retain(|query| !query.expired());

        // use this to group subnet queries together for a single discovery request
        let mut subnet_queries: Vec<SubnetQuery> = Vec::new();
        let mut processed = false;
        // Check that we are within our query concurrency limit
        while !self.at_capacity() && !self.queued_queries.is_empty() {
            // consume and process the query queue
            if let Some(subnet_query) = self.queued_queries.pop_front() {
                subnet_queries.push(subnet_query);

                // We want to start a grouped subnet query if:
                //  1. We've grouped MAX_SUBNETS_IN_QUERY subnets together.
                //  2. There are no more messages in the queue.
                if subnet_queries.len() == MAX_SUBNETS_IN_QUERY || self.queued_queries.is_empty() {
                    // This query is for searching for peers of a particular subnet
                    // Drain subnet_queries so we can re-use it as we continue to process the queue
                    let grouped_queries: Vec<SubnetQuery> = subnet_queries.drain(..).collect();
                    self.start_subnet_query(grouped_queries);
                    processed = true;
                }
            }
        }
        // Update the queue metric
        metrics::set_gauge(&metrics::DISCOVERY_QUEUE, self.queued_queries.len() as i64);
        processed
    }

    // Returns a boolean indicating if we are currently processing the maximum number of
    // concurrent subnet queries or not.
    fn at_capacity(&self) -> bool {
        self.active_queries
            .len()
            .saturating_sub(self.find_peer_active as usize) // We only count active subnet queries
            >= MAX_CONCURRENT_SUBNET_QUERIES
    }

    /// Runs a discovery request for a given group of subnets.
    fn start_subnet_query(&mut self, subnet_queries: Vec<SubnetQuery>) {
        let mut filtered_subnets: Vec<Subnet> = Vec::new();

        // find subnet queries that are still necessary
        let filtered_subnet_queries: Vec<SubnetQuery> = subnet_queries
            .into_iter()
            .filter(|subnet_query| {
                // Determine if we have sufficient peers, which may make this discovery unnecessary.
                let peers_on_subnet = self
                    .network_globals
                    .peers
                    .read()
                    .good_peers_on_subnet(subnet_query.subnet)
                    .count();

                if peers_on_subnet >= TARGET_SUBNET_PEERS {
                    debug!(self.log, "Discovery ignored";
                        "reason" => "Already connected to desired peers",
                        "connected_peers_on_subnet" => peers_on_subnet,
                        "target_subnet_peers" => TARGET_SUBNET_PEERS,
                    );
                    return false;
                }

                let target_peers = TARGET_SUBNET_PEERS - peers_on_subnet;
                trace!(self.log, "Discovery query started for subnet";
                    "subnet_query" => ?subnet_query,
                    "connected_peers_on_subnet" => peers_on_subnet,
                    "peers_to_find" => target_peers,
                );

                filtered_subnets.push(subnet_query.subnet);
                true
            })
            .collect();

        // Only start a discovery query if we have a subnet to look for.
        if !filtered_subnet_queries.is_empty() {
            // build the subnet predicate as a combination of the eth2_fork_predicate and the subnet predicate
            let subnet_predicate = subnet_predicate::<TSpec>(filtered_subnets, &self.log);

            debug!(
                self.log,
                "Starting grouped subnet query";
                "subnets" => ?filtered_subnet_queries,
            );
            self.start_query(
                QueryType::Subnet(filtered_subnet_queries),
                TARGET_PEERS_FOR_GROUPED_QUERY,
                subnet_predicate,
            );
        }
    }

    /// Search for a specified number of new peers using the underlying discovery mechanism.
    ///
    /// This can optionally search for peers for a given predicate. Regardless of the predicate
    /// given, this will only search for peers on the same enr_fork_id as specified in the local
    /// ENR.
    fn start_query(
        &mut self,
        query: QueryType,
        target_peers: usize,
        additional_predicate: impl Fn(&Enr) -> bool + Send + 'static,
    ) {
        // Make sure there are subnet queries included
        let contains_queries = match &query {
            QueryType::Subnet(queries) => !queries.is_empty(),
            QueryType::FindPeers => true,
        };

        if !contains_queries {
            debug!(
                self.log,
                "No subnets included in this request. Skipping discovery request."
            );
            return;
        }

        // Generate a random target node id.
        let random_node = NodeId::random();

        let enr_fork_id = match self.local_enr().eth2() {
            Ok(v) => v,
            Err(e) => {
                crit!(self.log, "Local ENR has no fork id"; "error" => e);
                return;
            }
        };
        // predicate for finding nodes with a matching fork and valid tcp port
        let eth2_fork_predicate = move |enr: &Enr| {
            // `next_fork_epoch` and `next_fork_version` can be different so that
            // we can connect to peers who aren't compatible with an upcoming fork.
            // `fork_digest` **must** be same.
            enr.eth2().map(|e| e.fork_digest) == Ok(enr_fork_id.fork_digest)
                && (enr.tcp().is_some() || enr.tcp6().is_some())
        };

        // General predicate
        let predicate: Box<dyn Fn(&Enr) -> bool + Send> =
            Box::new(move |enr: &Enr| eth2_fork_predicate(enr) && additional_predicate(enr));

        // Build the future
        let query_future = self
            .discv5
            .find_node_predicate(random_node, predicate, target_peers)
            .map(|v| QueryResult {
                query_type: query,
                result: v,
            });

        // Add the future to active queries, to be executed.
        self.active_queries.push(Box::pin(query_future));
    }

    /// Process the completed QueryResult returned from discv5.
    fn process_completed_queries(
        &mut self,
        query: QueryResult,
    ) -> Option<HashMap<PeerId, Option<Instant>>> {
        match query.query_type {
            QueryType::FindPeers => {
                self.find_peer_active = false;
                match query.result {
                    Ok(r) if r.is_empty() => {
                        debug!(self.log, "Discovery query yielded no results.");
                    }
                    Ok(r) => {
                        debug!(self.log, "Discovery query completed"; "peers_found" => r.len());
                        let mut results: HashMap<_, Option<Instant>> = HashMap::new();
                        r.iter().for_each(|enr| {
                            // cache the found ENR's
                            self.cached_enrs.put(enr.peer_id(), enr.clone());
                            results.insert(enr.peer_id(), None);
                        });
                        return Some(results);
                    }
                    Err(e) => {
                        warn!(self.log, "Discovery query failed"; "error" => %e);
                    }
                }
            }
            QueryType::Subnet(queries) => {
                let subnets_searched_for: Vec<Subnet> =
                    queries.iter().map(|query| query.subnet).collect();
                match query.result {
                    Ok(r) if r.is_empty() => {
                        debug!(self.log, "Grouped subnet discovery query yielded no results."; "subnets_searched_for" => ?subnets_searched_for);
                        queries.iter().for_each(|query| {
                            self.add_subnet_query(query.subnet, query.min_ttl, query.retries + 1);
                        })
                    }
                    Ok(r) => {
                        debug!(self.log, "Peer grouped subnet discovery request completed"; "peers_found" => r.len(), "subnets_searched_for" => ?subnets_searched_for);

                        let mut mapped_results = HashMap::new();

                        // cache the found ENR's
                        for enr in r.iter().cloned() {
                            self.cached_enrs.put(enr.peer_id(), enr);
                        }

                        // Map each subnet query's min_ttl to the set of ENR's returned for that subnet.
                        queries.iter().for_each(|query| {
                            // A subnet query has completed. Add back to the queue, incrementing retries.
                            self.add_subnet_query(query.subnet, query.min_ttl, query.retries + 1);

                            // Check the specific subnet against the enr
                            let subnet_predicate =
                                subnet_predicate::<TSpec>(vec![query.subnet], &self.log);

                            r.iter()
                                .filter(|enr| subnet_predicate(enr))
                                .map(|enr| enr.peer_id())
                                .for_each(|peer_id| {
                                    let other_min_ttl = mapped_results.get_mut(&peer_id);

                                    // map peer IDs to the min_ttl furthest in the future
                                    match (query.min_ttl, other_min_ttl) {
                                        // update the mapping if the min_ttl is greater
                                        (
                                            Some(min_ttl_instant),
                                            Some(Some(other_min_ttl_instant)),
                                        ) => {
                                            if min_ttl_instant
                                                .saturating_duration_since(*other_min_ttl_instant)
                                                > DURATION_DIFFERENCE
                                            {
                                                *other_min_ttl_instant = min_ttl_instant;
                                            }
                                        }
                                        // update the mapping if we have a specified min_ttl
                                        (Some(min_ttl), Some(None)) => {
                                            mapped_results.insert(peer_id, Some(min_ttl));
                                        }
                                        // first seen min_ttl for this enr
                                        (Some(min_ttl), None) => {
                                            mapped_results.insert(peer_id, Some(min_ttl));
                                        }
                                        // first seen min_ttl for this enr
                                        (None, None) => {
                                            mapped_results.insert(peer_id, None);
                                        }
                                        (None, Some(Some(_))) => {} // Don't replace the existing specific min_ttl
                                        (None, Some(None)) => {} // No-op because this is a duplicate
                                    }
                                });
                        });

                        if mapped_results.is_empty() {
                            return None;
                        } else {
                            return Some(mapped_results);
                        }
                    }
                    Err(e) => {
                        warn!(self.log,"Grouped subnet discovery query failed"; "subnets_searched_for" => ?subnets_searched_for, "error" => %e);
                    }
                }
            }
        }
        None
    }

    /// Drives the queries returning any results from completed queries.
    fn poll_queries(&mut self, cx: &mut Context) -> Option<HashMap<PeerId, Option<Instant>>> {
        while let Poll::Ready(Some(query_result)) = self.active_queries.poll_next_unpin(cx) {
            let result = self.process_completed_queries(query_result);
            if result.is_some() {
                return result;
            }
        }
        None
    }
}

/* NetworkBehaviour Implementation */

impl<TSpec: EthSpec> NetworkBehaviour for Discovery<TSpec> {
    // Discovery is not a real NetworkBehaviour...
    type ProtocolsHandler = libp2p::swarm::protocols_handler::DummyProtocolsHandler;
    type OutEvent = DiscoveryEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        libp2p::swarm::protocols_handler::DummyProtocolsHandler::default()
    }

    // Handles the libp2p request to obtain multiaddrs for peer_id's in order to dial them.
    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        if let Some(enr) = self.enr_of_peer(peer_id) {
            // ENR's may have multiple Multiaddrs. The multi-addr associated with the UDP
            // port is removed, which is assumed to be associated with the discv5 protocol (and
            // therefore irrelevant for other libp2p components).
            enr.multiaddr_tcp()
        } else {
            // PeerId is not known
            Vec::new()
        }
    }

    fn inject_connected(&mut self, _peer_id: &PeerId) {}
    fn inject_disconnected(&mut self, _peer_id: &PeerId) {}
    fn inject_connection_established(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _connected_point: &ConnectedPoint,
    ) {
    }
    fn inject_connection_closed(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _connected_point: &ConnectedPoint,
    ) {
    }
    fn inject_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        _: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
    }

    fn inject_dial_failure(&mut self, peer_id: &PeerId) {
        // set peer as disconnected in discovery DHT
        debug!(self.log, "Marking peer disconnected in DHT"; "peer_id" => %peer_id);
        self.disconnect_peer(peer_id);
    }

    // Main execution loop to drive the behaviour
    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NBAction<<Self::ProtocolsHandler as ProtocolsHandler>::InEvent, Self::OutEvent>> {
        if !self.started {
            return Poll::Pending;
        }

        // Process the query queue
        self.process_queue();

        // Drive the queries and return any results from completed queries
        if let Some(results) = self.poll_queries(cx) {
            // return the result to the peer manager
            return Poll::Ready(NBAction::GenerateEvent(DiscoveryEvent::QueryResult(
                results,
            )));
        }

        // Process the server event stream
        match self.event_stream {
            EventStream::Awaiting(ref mut fut) => {
                // Still awaiting the event stream, poll it
                if let Poll::Ready(event_stream) = fut.poll_unpin(cx) {
                    match event_stream {
                        Ok(stream) => {
                            debug!(self.log, "Discv5 event stream ready");
                            self.event_stream = EventStream::Present(stream);
                        }
                        Err(e) => {
                            slog::crit!(self.log, "Discv5 event stream failed"; "error" => %e);
                            self.event_stream = EventStream::InActive;
                        }
                    }
                }
            }
            EventStream::InActive => {} // ignore checking the stream
            EventStream::Present(ref mut stream) => {
                while let Poll::Ready(Some(event)) = stream.poll_recv(cx) {
                    match event {
                        // We filter out unwanted discv5 events here and only propagate useful results to
                        // the peer manager.
                        Discv5Event::Discovered(_enr) => {
                            // Peers that get discovered during a query but are not contactable or
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
                            info!(self.log, "Address updated"; "ip" => %socket.ip(), "udp_port" => %socket.port());
                            metrics::inc_counter(&metrics::ADDRESS_UPDATE_COUNT);
                            // Discv5 will have updated our local ENR. We save the updated version
                            // to disk.
                            let enr = self.discv5.local_enr();
                            enr::save_enr_to_disk(Path::new(&self.enr_dir), &enr, &self.log);
                            // update  network globals
                            *self.network_globals.local_enr.write() = enr;
                            return Poll::Ready(NBAction::GenerateEvent(
                                DiscoveryEvent::SocketUpdated(socket),
                            ));
                        }
                        Discv5Event::EnrAdded { .. }
                        | Discv5Event::TalkRequest(_)
                        | Discv5Event::NodeInserted { .. } => {} // Ignore all other discv5 server events
                    }
                }
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::methods::{MetaData, MetaDataV2};
    use enr::EnrBuilder;
    use slog::{o, Drain};
    use std::net::UdpSocket;
    use types::{BitVector, MinimalEthSpec, SubnetId};

    type E = MinimalEthSpec;

    pub fn unused_port() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("should create udp socket");
        let local_addr = socket.local_addr().expect("should read udp socket");
        local_addr.port()
    }

    pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        if enabled {
            slog::Logger::root(drain.filter_level(level).fuse(), o!())
        } else {
            slog::Logger::root(drain.filter(|_| false).fuse(), o!())
        }
    }

    async fn build_discovery() -> Discovery<E> {
        let keypair = libp2p::identity::Keypair::generate_secp256k1();
        let config = NetworkConfig {
            discovery_port: unused_port(),
            ..Default::default()
        };
        let enr_key: CombinedKey = CombinedKey::from_libp2p(&keypair).unwrap();
        let enr: Enr = build_enr::<E>(&enr_key, &config, EnrForkId::default()).unwrap();
        let log = build_log(slog::Level::Debug, false);
        let globals = NetworkGlobals::new(
            enr,
            9000,
            9000,
            MetaData::V2(MetaDataV2 {
                seq_number: 0,
                attnets: Default::default(),
                syncnets: Default::default(),
            }),
            vec![],
            &log,
        );
        Discovery::new(&keypair, &config, Arc::new(globals), &log)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_add_subnet_query() {
        let mut discovery = build_discovery().await;
        let now = Instant::now();
        let mut subnet_query = SubnetQuery {
            subnet: Subnet::Attestation(SubnetId::new(1)),
            min_ttl: Some(now),
            retries: 0,
        };
        discovery.add_subnet_query(
            subnet_query.subnet,
            subnet_query.min_ttl,
            subnet_query.retries,
        );
        assert_eq!(discovery.queued_queries.back(), Some(&subnet_query));

        // New query should replace old query
        subnet_query.min_ttl = Some(now + Duration::from_secs(1));
        discovery.add_subnet_query(subnet_query.subnet, subnet_query.min_ttl, 1);

        subnet_query.retries += 1;

        assert_eq!(discovery.queued_queries.len(), 1);
        assert_eq!(
            discovery.queued_queries.pop_back(),
            Some(subnet_query.clone())
        );

        // Retries > MAX_DISCOVERY_RETRY must return immediately without adding
        // anything.
        discovery.add_subnet_query(
            subnet_query.subnet,
            subnet_query.min_ttl,
            MAX_DISCOVERY_RETRY + 1,
        );

        assert_eq!(discovery.queued_queries.len(), 0);
    }

    fn make_enr(subnet_ids: Vec<usize>) -> Enr {
        let mut builder = EnrBuilder::new("v4");
        let keypair = libp2p::identity::Keypair::generate_secp256k1();
        let enr_key: CombinedKey = CombinedKey::from_libp2p(&keypair).unwrap();

        // set the "attnets" field on our ENR
        let mut bitfield = BitVector::<ssz_types::typenum::U64>::new();
        for id in subnet_ids {
            bitfield.set(id, true).unwrap();
        }

        builder.add_value(ATTESTATION_BITFIELD_ENR_KEY, &bitfield.as_ssz_bytes());
        builder.build(&enr_key).unwrap()
    }

    #[tokio::test]
    async fn test_completed_subnet_queries() {
        let mut discovery = build_discovery().await;
        let now = Instant::now();
        let instant1 = Some(now + Duration::from_secs(10));
        let instant2 = Some(now + Duration::from_secs(5));

        let query = QueryType::Subnet(vec![
            SubnetQuery {
                subnet: Subnet::Attestation(SubnetId::new(1)),
                min_ttl: instant1,
                retries: 0,
            },
            SubnetQuery {
                subnet: Subnet::Attestation(SubnetId::new(2)),
                min_ttl: instant2,
                retries: 0,
            },
        ]);

        // Create enr which is subscribed to subnets 1 and 2
        let enr1 = make_enr(vec![1, 2]);
        let enr2 = make_enr(vec![2]);
        // Unwanted enr for the given grouped query
        let enr3 = make_enr(vec![3]);

        let enrs: Vec<Enr> = vec![enr1.clone(), enr2, enr3];
        let results = discovery
            .process_completed_queries(QueryResult {
                query_type: query,
                result: Ok(enrs),
            })
            .unwrap();

        // enr1 and enr2 are required peers based on the requested subnet ids
        assert_eq!(results.len(), 2);

        // when a peer belongs to multiple subnet ids, we use the highest ttl.
        assert_eq!(results.get(&enr1.peer_id()).unwrap(), &instant1);
    }
}
