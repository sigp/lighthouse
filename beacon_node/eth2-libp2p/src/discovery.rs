use crate::metrics;
use crate::{error, NetworkConfig};
/// This manages the discovery and management of peers.
///
/// Currently using discv5 for peer discovery.
///
use futures::prelude::*;
use libp2p::core::{identity::Keypair, ConnectedPoint, Multiaddr, PeerId};
use libp2p::discv5::{Discv5, Discv5Event};
use libp2p::enr::{Enr, EnrBuilder, NodeId};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction, PollParameters, ProtocolsHandler};
use slog::{debug, info, warn};
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_timer::Delay;

/// Maximum seconds before searching for extra peers.
const MAX_TIME_BETWEEN_PEER_SEARCHES: u64 = 60;
/// Initial delay between peer searches.
const INITIAL_SEARCH_DELAY: u64 = 5;
/// Local ENR storage filename.
const ENR_FILENAME: &str = "enr.dat";

/// Lighthouse discovery behaviour. This provides peer management and discovery using the Discv5
/// libp2p protocol.
pub struct Discovery<TSubstream> {
    /// The peers currently connected to libp2p streams.
    connected_peers: HashSet<PeerId>,

    /// The target number of connected peers on the libp2p interface.
    max_peers: usize,

    /// directory to save ENR to
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

    /// Logger for the discovery behaviour.
    log: slog::Logger,
}

impl<TSubstream> Discovery<TSubstream> {
    pub fn new(
        local_key: &Keypair,
        config: &NetworkConfig,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        let log = log.clone();

        // checks if current ENR matches that found on disk
        let local_enr = load_enr(local_key, config, &log)?;

        let enr_dir = match config.network_dir.to_str() {
            Some(path) => String::from(path),
            None => String::from(""),
        };

        info!(log, "ENR Initialised"; "ENR" => local_enr.to_base64(), "Seq" => local_enr.seq());
        debug!(log, "Discv5 Node ID Initialised"; "node_id" => format!("{}",local_enr.node_id()));

        let mut discovery = Discv5::new(local_enr, local_key.clone(), config.listen_address)
            .map_err(|e| format!("Discv5 service failed. Error: {:?}", e))?;

        // Add bootnodes to routing table
        for bootnode_enr in config.boot_nodes.clone() {
            debug!(
                log,
                "Adding node to routing table";
                "Node ID" => format!("{}",
                bootnode_enr.node_id())
            );
            discovery.add_enr(bootnode_enr);
        }

        Ok(Self {
            connected_peers: HashSet::new(),
            max_peers: config.max_peers,
            peer_discovery_delay: Delay::new(Instant::now()),
            past_discovery_delay: INITIAL_SEARCH_DELAY,
            tcp_port: config.libp2p_port,
            discovery,
            log,
            enr_dir,
        })
    }

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
        self.discovery.add_enr(enr);
    }

    /// The current number of connected libp2p peers.
    pub fn connected_peers(&self) -> usize {
        self.connected_peers.len()
    }

    /// The current number of connected libp2p peers.
    pub fn connected_peer_set(&self) -> &HashSet<PeerId> {
        &self.connected_peers
    }

    /// Search for new peers using the underlying discovery mechanism.
    fn find_peers(&mut self) {
        // pick a random NodeId
        let random_node = NodeId::random();
        debug!(self.log, "Searching for peers");
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
        // TODO: Drop peers if over max_peer limit

        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        metrics::set_gauge(&metrics::PEERS_CONNECTED, self.connected_peers() as i64);
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId, _endpoint: ConnectedPoint) {
        self.connected_peers.remove(peer_id);

        metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
        metrics::set_gauge(&metrics::PEERS_CONNECTED, self.connected_peers() as i64);
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
                    if self.connected_peers.len() < self.max_peers {
                        self.find_peers();
                    }
                }
                Ok(Async::NotReady) => break,
                Err(e) => {
                    warn!(self.log, "Discovery peer search failed"; "Error" => format!("{:?}", e));
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
                            info!(self.log, "Address updated"; "IP" => format!("{}",socket.ip()));
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
                            if closer_peers.is_empty() {
                                debug!(self.log, "Discovery random query found no peers");
                            }
                            for peer_id in closer_peers {
                                // if we need more peers, attempt a connection
                                if self.connected_peers.len() < self.max_peers
                                    && self.connected_peers.get(&peer_id).is_none()
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
) -> Result<Enr, String> {
    // Build the local ENR.
    // Note: Discovery should update the ENR record's IP to the external IP as seen by the
    // majority of our peers.
    let mut local_enr = EnrBuilder::new()
        .ip(config.discovery_address)
        .tcp(config.libp2p_port)
        .udp(config.discovery_port)
        .build(&local_key)
        .map_err(|e| format!("Could not build Local ENR: {:?}", e))?;

    let enr_f = config.network_dir.join(ENR_FILENAME);
    if let Ok(mut enr_file) = File::open(enr_f.clone()) {
        let mut enr_string = String::new();
        match enr_file.read_to_string(&mut enr_string) {
            Err(_) => debug!(log, "Could not read ENR from file"),
            Ok(_) => {
                match Enr::from_str(&enr_string) {
                    Ok(enr) => {
                        if enr.node_id() == local_enr.node_id() {
                            if enr.ip() == config.discovery_address.into()
                                && enr.tcp() == Some(config.libp2p_port)
                                && enr.udp() == Some(config.discovery_port)
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
