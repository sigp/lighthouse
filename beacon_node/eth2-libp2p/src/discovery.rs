use crate::metrics;
use crate::{error, NetworkConfig, NetworkGlobals, PeerInfo};
/// This manages the discovery and management of peers.
///
/// Currently using discv5 for peer discovery.
///
use futures::prelude::*;
use libp2p::core::{identity::Keypair, ConnectedPoint, Multiaddr, PeerId};
use libp2p::discv5::enr::{CombinedKey, Enr, EnrBuilder, NodeId};
use libp2p::discv5::{Discv5, Discv5ConfigBuilder, Discv5Event};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction, PollParameters, ProtocolsHandler};
use slog::{debug, info, warn};
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::timer::Delay;
use types::EthSpec;

/// Maximum seconds before searching for extra peers.
const MAX_TIME_BETWEEN_PEER_SEARCHES: u64 = 120;
/// Initial delay between peer searches.
const INITIAL_SEARCH_DELAY: u64 = 5;
/// Local ENR storage filename.
const ENR_FILENAME: &str = "enr.dat";

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
        network_globals: Arc<NetworkGlobals<TSpec>>,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        let log = log.clone();

        // checks if current ENR matches that found on disk
        let local_enr = load_enr(local_key, config, &log)?;

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
            config.discv5_config,
            config.listen_address,
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
            discovery.add_enr(bootnode_enr);
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
    pub fn local_enr(&self) -> &Enr<CombinedKey> {
        self.discovery.local_enr()
    }

    /// Manually search for peers. This restarts the discovery round, sparking multiple rapid
    /// queries.
    pub fn discover_peers(&mut self) {
        self.past_discovery_delay = INITIAL_SEARCH_DELAY;
        self.find_peers();
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr<CombinedKey>) {
        self.discovery.add_enr(enr);
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
    pub fn enr_entries(&mut self) -> impl Iterator<Item = &Enr<CombinedKey>> {
        self.discovery.enr_entries()
    }

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
        // TODO: Search for a known ENR once discv5 is updated.
        self.network_globals
            .connected_peer_set
            .write()
            .insert(peer_id, PeerInfo::new());
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
                            save_enr_to_disc(Path::new(&self.enr_dir), enr, &self.log);

                            return Async::Ready(NetworkBehaviourAction::ReportObservedAddr {
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

/// Loads an ENR from file if it exists and matches the current NodeId and sequence number. If none
/// exists, generates a new one.
///
/// If an ENR exists, with the same NodeId and IP address, we use the disk-generated one as its
/// ENR sequence will be equal or higher than a newly generated one.
fn load_enr(
    local_key: &Keypair,
    config: &NetworkConfig,
    log: &slog::Logger,
) -> Result<Enr<CombinedKey>, String> {
    // Build the local ENR.
    // Note: Discovery should update the ENR record's IP to the external IP as seen by the
    // majority of our peers, if the CLI doesn't expressly forbid it.
    let enr_key: CombinedKey = local_key
        .try_from()
        .map_err(|_| "Invalid key type for ENR records")?;

    let mut local_enr = {
        let mut builder = EnrBuilder::new("v4");
        if let Some(enr_address) = config.enr_address {
            builder.ip(discovery_address);
        }
        if let Some(udp_port) = config.enr_udp_port {
            builder.udp(config.udp_port);
        }

        builder
            .tcp(config.libp2p_port)
            .build(&enr_key)
            .map_err(|e| format!("Could not build Local ENR: {:?}", e))?;
    };

    let enr_f = config.network_dir.join(ENR_FILENAME);
    if let Ok(mut enr_file) = File::open(enr_f.clone()) {
        let mut enr_string = String::new();
        match enr_file.read_to_string(&mut enr_string) {
            Err(_) => debug!(log, "Could not read ENR from file"),
            Ok(_) => {
                match Enr::from_str(&enr_string) {
                    Ok(enr) => {
                        if enr.node_id() == local_enr.node_id() {
                            if (config.enr_address.is_none()
                                || enr.ip().map(Into::into) == config.enr_address)
                                && enr.tcp() == Some(config.libp2p_port)
                                && (config.enr_udp_port.is_none()
                                    || enr.udp() == Some(config.enr_port))
                            {
                                debug!(log, "ENR loaded from file"; "file" => format!("{:?}", enr_f));
                                // the stored ENR has the same configuration, use it
                                return Ok(enr);
                            }

                            // same node id, different configuration - update the sequence number
                            let new_seq_no = enr.seq().checked_add(1).ok_or_else(|| "ENR sequence number on file is too large. Remove it to generate a new NodeId")?;
                            local_enr.set_seq(new_seq_no, local_key).map_err(|e| {
                                format!("Could not update ENR sequence number: {:?}", e)
                            })?;
                            debug!(log, "ENR sequence number increased"; "seq" =>  new_seq_no);
                        }
                    }
                    Err(e) => {
                        warn!(log, "ENR from file could not be decoded"; "error" => format!("{:?}", e));
                    }
                }
            }
        }
    }

    save_enr_to_disc(&config.network_dir, &local_enr, log);

    Ok(local_enr)
}

fn save_enr_to_disc(dir: &Path, enr: &Enr, log: &slog::Logger) {
    let _ = std::fs::create_dir_all(dir);
    match File::create(dir.join(Path::new(ENR_FILENAME)))
        .and_then(|mut f| f.write_all(&enr.to_base64().as_bytes()))
    {
        Ok(_) => {
            debug!(log, "ENR written to disk");
        }
        Err(e) => {
            warn!(
                log,
                "Could not write ENR to file"; "file" => format!("{:?}{:?}",dir, ENR_FILENAME),  "error" => format!("{}", e)
            );
        }
    }
}
