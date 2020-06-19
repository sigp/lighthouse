///! This manages the discovery and management of peers.
pub(crate) mod enr;
pub mod enr_ext;

// Allow external use of the lighthouse ENR builder
pub use enr::{build_enr, CombinedKey, Eth2Enr};
pub use enr_ext::{CombinedKeyExt, EnrExt};
pub use libp2p::core::identity::Keypair;

use crate::metrics;
use crate::{error, Enr, NetworkConfig, NetworkGlobals};
use discv5::{enr::NodeId, Discv5, Discv5Event};
use enr::{BITFIELD_ENR_KEY, ETH2_ENR_KEY};
use futures::prelude::*;
use libp2p::core::PeerId;
// use libp2p::multiaddr::Protocol;
use futures::stream::FuturesUnordered;
use lru::LruCache;
use slog::{crit, debug, info, trace, warn};
use ssz::{Decode, Encode};
use ssz_types::BitVector;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tokio::sync::mpsc;
use types::{EnrForkId, EthSpec, SubnetId};

mod subnet_predicate;
use subnet_predicate::subnet_predicate;

/// Local ENR storage filename.
pub const ENR_FILENAME: &str = "enr.dat";
/// Target number of peers we'd like to have connected to a given long-lived subnet.
const TARGET_SUBNET_PEERS: usize = 3;
/// Number of times to attempt a discovery request
const MAX_DISCOVERY_RETRY: usize = 3;
/// The maximum number of concurrent discovery queries.
const MAX_CONCURRENT_QUERIES: usize = 1;
/// The number of closest peers to search for when doing a regular peer search.
///
/// We could reduce this constant to speed up queries however at the cost of security. It will
/// make it easier to peers to eclipse this node. Kademlia suggests a value of 16.
const FIND_NODE_QUERY_CLOSEST_PEERS: usize = 16;

/// The events emitted by polling discovery.
pub enum DiscoveryEvent {
    /// A query has completed. The first parameter is the `min_ttl` of the peers if it is specified
    /// and the second parameter are the discovered peers.
    QueryResult(Option<Instant>, Box<Vec<Enr>>),
    /// This indicates that our local UDP socketaddr has been updated and we should inform libp2p.
    SocketUpdated(SocketAddr),
}

#[derive(Debug, Clone, PartialEq)]
enum QueryType {
    /// We are searching for subnet peers.
    Subnet {
        subnet_id: SubnetId,
        min_ttl: Option<Instant>,
        retries: usize,
    },
    /// We are searching for more peers without ENR or time constraints.
    FindPeers,
}

impl QueryType {
    /// Returns true if this query has expired.
    pub fn expired(&self) -> bool {
        match self {
            Self::FindPeers => false,
            Self::Subnet { min_ttl, .. } => {
                if let Some(ttl) = min_ttl {
                    ttl > &Instant::now()
                } else {
                    true
                }
            }
        }
    }

    /// Returns the min_ttl of the query if one exists
    ///
    /// This is required for returning to the peer manager. The peer manager will update newly
    /// connected peers with this `min_ttl`
    pub fn min_ttl(&self) -> Option<Instant> {
        match self {
            Self::FindPeers => None,
            Self::Subnet { min_ttl, .. } => min_ttl.clone(),
        }
    }
}

/// The result of a query.
struct QueryResult(QueryType, Result<Vec<Enr>, discv5::QueryError>);

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
    // The future has failed, there are no events from discv5.
    Failed,
}

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

    /// A queue of discovery queries to be processed.
    queued_queries: VecDeque<QueryType>,

    /// Active discovery queries.
    active_queries: FuturesUnordered<std::pin::Pin<Box<dyn Future<Output = QueryResult> + Send>>>,

    /// The discv5 event stream.
    event_stream: EventStream,

    /// Logger for the discovery behaviour.
    log: slog::Logger,
}

impl<TSpec: EthSpec> Discovery<TSpec> {
    /// NOTE: Creating discovery requires running within a tokio execution environment.
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

        let mut discv5 = Discv5::new(local_enr, enr_key, config.discv5_config.clone())
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
            let _ = discv5.add_enr(bootnode_enr).map_err(|e| {
                warn!(
                    log,
                    "Could not add peer to the local routing table";
                    "error" => format!("{}", e)
                )
            });
        }

        // start the discv5 service.
        discv5.start(listen_socket);
        debug!(log, "Discovery service started");

        // obtain the event stream
        let event_stream = EventStream::Awaiting(Box::pin(discv5.event_stream()));

        Ok(Self {
            cached_enrs: LruCache::new(50),
            network_globals,
            find_peer_active: false,
            queued_queries: VecDeque::with_capacity(10),
            active_queries: FuturesUnordered::new(),
            discv5,
            event_stream,
            log,
            enr_dir,
        })
    }

    /// Return the nodes local ENR.
    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// This adds a new `FindPeers` query to the queue if one doesn't already exist.
    pub fn discover_peers(&mut self) {
        // If there is not already a find peer's query queued, add one
        let query = QueryType::FindPeers;
        if !self.queued_queries.contains(&query) {
            trace!(self.log, "Queuing a peer discovery request");
            self.queued_queries.push_back(query);
            // update the metrics
            metrics::set_gauge(&metrics::DISCOVERY_QUEUE, self.queued_queries.len() as i64);
        }
    }

    /// Processes a request to search for more peers on a subnet.
    pub fn discover_subnet_peers(&mut self, subnet_id: SubnetId, min_ttl: Option<Instant>) {
        self.add_subnet_query(subnet_id, min_ttl, 0);
    }

    /// Adds a subnet query if one doesn't exist. If a subnet query already exists, this
    /// updates the min_ttl field.
    fn add_subnet_query(&mut self, subnet_id: SubnetId, min_ttl: Option<Instant>, retries: usize) {
        // remove the entry and complete the query if greater than the maximum search count
        if retries >= MAX_DISCOVERY_RETRY {
            debug!(
                self.log,
                "Subnet peer discovery did not find sufficient peers. Reached max retry limit"
            );
            return;
        }

        // Search through any queued requests and update the timeout if a query for this subnet
        // already exists
        let mut found = false;
        for query in self.queued_queries.iter_mut() {
            if let QueryType::Subnet {
                subnet_id: ref mut q_subnet_id,
                min_ttl: ref mut q_min_ttl,
                retries: ref mut q_retries,
            } = query
            {
                if *q_subnet_id == subnet_id {
                    if *q_min_ttl < min_ttl {
                        *q_min_ttl = min_ttl;
                    }
                    // update the number of retries
                    *q_retries = retries;
                    // mimic an `Iter::Find()` and short-circuit the loop
                    found = true;
                    break;
                }
            }
        }
        if !found {
            // Set up the query and add it to the queue
            let query = QueryType::Subnet {
                subnet_id,
                min_ttl,
                retries,
            };
            // update the metrics and insert into the queue.
            metrics::set_gauge(&metrics::DISCOVERY_QUEUE, self.queued_queries.len() as i64);
            self.queued_queries.push_back(query);
        }
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        // add the enr to seen caches
        self.cached_enrs.put(enr.peer_id(), enr.clone());

        if let Err(e) = self.discv5.add_enr(enr) {
            warn!(
                self.log,
                "Could not add peer to the local routing table";
                "error" => format!("{}", e)
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

    /// Adds/Removes a subnet from the ENR Bitfield
    pub fn update_enr_bitfield(&mut self, subnet_id: SubnetId, value: bool) -> Result<(), String> {
        let id = *subnet_id as usize;

        let local_enr = self.discv5.local_enr();
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
            .discv5
            .enr_insert(BITFIELD_ENR_KEY, current_bitfield.as_ssz_bytes());

        // replace the global version
        *self.network_globals.local_enr.write() = self.discv5.local_enr().clone();
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
            .discv5
            .enr_insert(ETH2_ENR_KEY.into(), enr_fork_id.as_ssz_bytes())
            .map_err(|e| {
                warn!(
                    self.log,
                    "Could not update eth2 ENR field";
                    "error" => format!("{:?}", e)
                )
            });

        // replace the global version with discovery version
        *self.network_globals.local_enr.write() = self.discv5.local_enr().clone();
    }

    /* Internal Functions */

    /// Consume the discovery queue and initiate queries when applicable.
    ///
    /// This also sanitizes the queue removing out-dated queries.
    fn process_queue(&mut self) {
        // Sanitize the queue, removing any out-dated subnet queries
        self.queued_queries.retain(|query| !query.expired());

        // Check that we are within our query concurrency limit
        while !self.at_capacity() && !self.queued_queries.is_empty() {
            // consume and process the query queue
            match self.queued_queries.pop_front() {
                Some(QueryType::FindPeers) => {
                    // Only permit one FindPeers query at a time
                    if self.find_peer_active {
                        self.queued_queries.push_back(QueryType::FindPeers);
                        continue;
                    }
                    // This is a regular request to find additional peers
                    debug!(self.log, "Searching for new peers");
                    self.find_peer_active = true;
                    self.start_query(QueryType::FindPeers, FIND_NODE_QUERY_CLOSEST_PEERS);
                }
                Some(QueryType::Subnet {
                    subnet_id,
                    min_ttl,
                    retries,
                }) => {
                    // This query is for searching for peers of a particular subnet
                    self.start_subnet_query(subnet_id, min_ttl, retries);
                }
                None => {} // Queue is empty
            }
        }
    }

    // Returns a boolean indicating if we are currently processing the maximum number of
    // concurrent queries or not.
    fn at_capacity(&self) -> bool {
        if self.active_queries.len() >= MAX_CONCURRENT_QUERIES {
            true
        } else {
            false
        }
    }

    /// Runs a discovery request for a given subnet_id if one already exists.
    fn start_subnet_query(
        &mut self,
        subnet_id: SubnetId,
        min_ttl: Option<Instant>,
        retries: usize,
    ) {
        // Determine if we have sufficient peers, which may make this discovery unnecessary.
        let peers_on_subnet = self
            .network_globals
            .peers
            .read()
            .peers_on_subnet(subnet_id)
            .count();

        if peers_on_subnet > TARGET_SUBNET_PEERS {
            trace!(self.log, "Discovery ignored";
                "reason" => "Already connected to desired peers",
                "connected_peers_on_subnet" => peers_on_subnet,
                "target_subnet_peers" => TARGET_SUBNET_PEERS,
            );
            return;
        }

        let target_peers = TARGET_SUBNET_PEERS - peers_on_subnet;
        debug!(self.log, "Searching for peers for subnet";
            "subnet_id" => *subnet_id,
            "connected_peers_on_subnet" => peers_on_subnet,
            "target_subnet_peers" => TARGET_SUBNET_PEERS,
            "peers_to_find" => target_peers,
            "attempt" => retries,
        );

        // start the query, and update the queries map if necessary
        let query = QueryType::Subnet {
            subnet_id,
            min_ttl,
            retries,
        };
        self.start_query(query, target_peers);
    }

    /// Search for a specified number of new peers using the underlying discovery mechanism.
    ///
    /// This can optionally search for peers for a given predicate. Regardless of the predicate
    /// given, this will only search for peers on the same enr_fork_id as specified in the local
    /// ENR.
    fn start_query(&mut self, query: QueryType, target_peers: usize) {
        // Generate a random target node id.
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

        // General predicate
        let predicate: Box<dyn Fn(&Enr) -> bool + Send> = match &query {
            QueryType::FindPeers => Box::new(eth2_fork_predicate),
            QueryType::Subnet { subnet_id, .. } => {
                // build the subnet predicate as a combination of the eth2_fork_predicate and the
                // subnet predicate
                let subnet_predicate = subnet_predicate::<TSpec>(subnet_id.clone(), &self.log);
                Box::new(move |enr: &Enr| eth2_fork_predicate(enr) && subnet_predicate(enr))
            }
        };

        // Build the future
        let query_future = self
            .discv5
            .find_node_predicate(random_node, predicate, target_peers)
            .map(|v| QueryResult(query, v));

        // Add the future to active queries, to be executed.
        self.active_queries.push(Box::pin(query_future));
    }

    /// Drives the queries returning any results from completed queries.
    fn poll_queries(&mut self, cx: &mut Context) -> Option<(Option<Instant>, Vec<Enr>)> {
        while let Poll::Ready(Some(query_future)) = self.active_queries.poll_next_unpin(cx) {
            match query_future.0 {
                QueryType::FindPeers => {
                    self.find_peer_active = false;
                    match query_future.1 {
                        Ok(r) if r.is_empty() => {
                            debug!(self.log, "Discovery query yielded no results.");
                        }
                        Ok(r) => {
                            debug!(self.log, "Discovery query completed"; "peers_found" => r.len());
                            return Some((None, r));
                        }
                        Err(e) => {
                            warn!(self.log, "Discovery query failed"; "error" => e.to_string());
                        }
                    }
                }
                QueryType::Subnet {
                    subnet_id,
                    min_ttl,
                    retries,
                } => {
                    match query_future.1 {
                        Ok(r) if r.is_empty() => {
                            debug!(self.log, "Subnet discovery query yielded no results."; "subnet_id" => *subnet_id, "retries" => retries);
                        }
                        Ok(r) => {
                            debug!(self.log, "Peer subnet discovery request completed"; "peers_found" => r.len(), "subnet_id" => *subnet_id);
                            // A subnet query has completed. Add back to the queue, incrementing retries.
                            self.add_subnet_query(subnet_id, min_ttl, retries + 1);
                            // Report the results back to the peer manager.
                            return Some((query_future.0.min_ttl(), r));
                        }
                        Err(e) => {
                            warn!(self.log,"Subnet Discovery query failed"; "subnet_id" => *subnet_id, "error" => e.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    // Main execution loop to be driven by the peer manager.
    pub fn poll(&mut self, cx: &mut Context) -> Poll<DiscoveryEvent> {
        // Process the query queue
        self.process_queue();

        // Drive the queries and return any results from completed queries
        if let Some((min_ttl, result)) = self.poll_queries(cx) {
            // cache the found ENR's
            for enr in result.iter().cloned() {
                self.cached_enrs.put(enr.peer_id(), enr);
            }
            // return the result to the peer manager
            return Poll::Ready(DiscoveryEvent::QueryResult(min_ttl, Box::new(result)));
        }

        // Process the server event stream
        match self.event_stream {
            EventStream::Awaiting(ref mut fut) => {
                // Still awaiting the event stream, poll it
                if let Poll::Ready(event_stream) = fut.poll_unpin(cx) {
                    match event_stream {
                        Ok(stream) => self.event_stream = EventStream::Present(stream),
                        Err(e) => {
                            slog::crit!(self.log, "Discv5 event stream failed"; "error" => e.to_string());
                            self.event_stream = EventStream::Failed;
                        }
                    }
                }
            }
            EventStream::Failed => {} // ignore checking the stream
            EventStream::Present(ref mut stream) => {
                while let Ok(event) = stream.try_recv() {
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
                            info!(self.log, "Address updated"; "ip" => format!("{}",socket.ip()), "udp_port" => format!("{}", socket.port()));
                            metrics::inc_counter(&metrics::ADDRESS_UPDATE_COUNT);
                            // Discv5 will have updated our local ENR. We save the updated version
                            // to disk.
                            let enr = self.discv5.local_enr();
                            enr::save_enr_to_disk(Path::new(&self.enr_dir), &enr, &self.log);
                            return Poll::Ready(DiscoveryEvent::SocketUpdated(socket));
                        }
                        _ => {} // Ignore all other discv5 server events
                    }
                }
            }
        }
        Poll::Pending
    }
}
