mod common;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use common::behaviours::{MethodCall, PuppetBehaviour, PuppetEvent};
use futures::StreamExt;
use libp2p::core::connection::{ConnectedPoint, ConnectionId};
use libp2p::swarm::protocols_handler::DummyProtocolsHandler;
use libp2p::swarm::{
    CloseConnection, DialError, DialPeerCondition, DummyBehaviour, IntoProtocolsHandler,
    NetworkBehaviour, NetworkBehaviourAction as NBAction, PollParameters, ProtocolsHandler, Swarm,
};
use libp2p::{development_transport, Multiaddr, NetworkBehaviour, PeerId};
use parking_lot::RwLock;
use slog::{debug, o};
use tokio;

#[derive(Debug)]
struct Event(());

#[derive(NetworkBehaviour)]
#[behaviour(event_process = false)]
struct Behaviour {
    /// Behaviour used to fake other sibling behaviour's "calls" to the swarm. It also registers
    /// calls from the swarm to the behaviour.
    pub puppet: PuppetBehaviour,
    pub conn_tracker: ConnTracker,
}

/* Connection tracker implementation */

enum ConnectionStatus {
    Connected {
        connections: HashMap<ConnectionId, (ConnectedPoint, Instant)>,
        disconnections: HashSet<ConnectionId>,
    },
    Disconnected {
        since: Instant,
    },
}

struct PeerInfo {
    connection_status: ConnectionStatus,
    dialing_attempts: u16,
}

struct ConnTracker {
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
}

impl NetworkBehaviour for ConnTracker {
    type ProtocolsHandler = DummyProtocolsHandler;

    type OutEvent = ();

    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        vec![]
    }

    fn inject_connected(&mut self, peer_id: &PeerId) {
        // This is the first time the peer connects to us. Thus the peer must be either new or be
        // disconnected. Check this. The connection will be registered in
        // `inject_connection_established`.
        // if let Some(info) = self.peers.read().get(peer_id) {
        //     assert!(matches!(
        //         info.connection_status,
        //         ConnectionStatus::Disconnected { .. }
        //     ))
        // }
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId) {
        // This is the last connection to this peer. Check that the peer exists, is connected, and
        // has only one active connection. The disconnection will be registered in
        // `inject_connection_closed`.

        // NOTE: called after inject_connection_closed
        // let peers = self.peers.read();
        // let info = peers.get(peer_id).expect("Peer exists");
        // match &info.connection_status {
        //     ConnectionStatus::Connected {
        //         connections,
        //         disconnections: _,
        //     } => {
        //         assert_eq!(
        //             connections.len(),
        //             1,
        //             "Disconnected notification must be for peer with only one connection"
        //         )
        //     }
        //     ConnectionStatus::Disconnected { since } => {
        //         panic!("Peer was already disconnected. Since: {:?}", since)
        //     }
        // }
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
    ) {
        match self.peers.write().entry(*peer_id) {
            Entry::Occupied(mut entry) => {
                let info = entry.get_mut();
                if matches!(endpoint, ConnectedPoint::Dialer { .. }) {
                    // Another behaviour could have dialed this peer via a multiaddr, and we
                    // wouldn't be aware of the dialing attempt for this peer.

                    /*
                     * Dialing / Disconnecting stuff
                     */
                    // info.dialing_attempts = info.dialing_attempts.saturating_sub(1);

                    // About this subtraction. The successful dialing attempts must be always
                    // more than the registered/known dialing attempts.
                }
                // now register the connection.
                match &mut info.connection_status {
                    ConnectionStatus::Connected {
                        connections,
                        disconnections: _,
                    } => {
                        assert!(
                            connections
                                .insert(connection_id.clone(), (endpoint.clone(), Instant::now()))
                                .is_none(),
                            "inject_connection_established is called only once per ConnectionId"
                        );
                    }
                    ConnectionStatus::Disconnected { since: _ } => {
                        // register the connection
                        let mut connections = HashMap::with_capacity(1);
                        connections
                            .insert(connection_id.clone(), (endpoint.clone(), Instant::now()));
                        let disconnections = HashSet::new();
                        info.connection_status = ConnectionStatus::Connected {
                            connections,
                            disconnections,
                        };
                    }
                }
            }
            Entry::Vacant(entry) => {
                // Peer is new
                let mut connections = HashMap::with_capacity(1);
                connections.insert(connection_id.clone(), (endpoint.clone(), Instant::now()));
                let disconnections = HashSet::new();
                entry.insert(PeerInfo {
                    connection_status: ConnectionStatus::Connected {
                        connections,
                        disconnections,
                    },
                    dialing_attempts: 0,
                });
            }
        }
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        _handler: Self::ProtocolsHandler,
    ) {
        let mut peers = self.peers.write();
        let info = peers.get_mut(peer_id).expect("Peer exists.");
        match &mut info.connection_status {
            ConnectionStatus::Connected {
                connections,
                disconnections,
            } => {
                // If we disconnect because we asked it, remove this disconnection attempt.
                disconnections.remove(connection_id);
                let (old_endpoint, _connection_instant) = connections
                    .remove(connection_id)
                    .expect("Closed connection was registered.");
                assert_eq!(endpoint, &old_endpoint);
                if connections.is_empty() {
                    info.connection_status = ConnectionStatus::Disconnected {
                        since: Instant::now(),
                    };
                }
            }
            ConnectionStatus::Disconnected { since } => panic!(
                "Connection closed for a peer disconnected since {:?}",
                since
            ),
        }
    }

    fn inject_address_change(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        let mut peers = self.peers.write();
        let info = peers.get_mut(peer_id).expect("Peer exists.");
        match &mut info.connection_status {
            ConnectionStatus::Connected {
                connections,
                disconnections: _,
            } => match connections.entry(*connection_id) {
                Entry::Occupied(mut entry) => {
                    let (old_registered, _) = entry.get_mut();
                    assert_eq!(old_registered, old);
                    *old_registered = new.clone();
                }
                Entry::Vacant(_) => panic!("Address change for connection not registered."),
            },
            ConnectionStatus::Disconnected { since } => {
                panic!("Address change for a peer disconnected since {:?}", since)
            }
        }
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ProtocolsHandler,
        _error: &DialError,
    ) {
        /*
         * Dialing / Disconnecting stuff
         */
        // if let Some(peer_id) = peer_id {
        //     // This was an explicit dial to a peer. We should have it registered.
        //     let mut peers = self.peers.write();
        //     let info = peers.get_mut(&peer_id).expect("Peer exists.");
        //     assert!(info.dialing_attempts > 0);
        //     info.dialing_attempts -= 1;
        // }
    }

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DummyProtocolsHandler::default()
    }

    fn inject_event(
        &mut self,
        _peer_id: PeerId,
        _connection: ConnectionId,
        _event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        unreachable!("No events from dummy handler.")
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
        _params: &mut impl lighthouse_network::discovery::PollParameters,
    ) -> Poll<NBAction<Self::OutEvent, Self::ProtocolsHandler>> {
        Poll::Pending
    }
}

// #[derive(NetworkBehaviour)]
// #[behaviour(event_process = false, out_event="E")]
// struct ConnTracked<IH = H, H, B, E>
// where
// IH: IntoProtocolsHandler<Handler = H>,
// H : ProtocolsHandler,
// E: Send + 'static,
// B: NetworkBehaviour<ProtocolsHandler = IH, OutEvent = E>,
// { // NOTE: can't make the derive work
struct ConnTracked<B> {
    // #[behaviour(ignore)]
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    b: B,
}

/*
 * NOTE: This is the price we pay to get disconnections and dialing_attempts
 */
impl<P: ProtocolsHandler, B: NetworkBehaviour<ProtocolsHandler = P>> NetworkBehaviour
    for ConnTracked<B>
{
    type ProtocolsHandler = B::ProtocolsHandler;

    type OutEvent = B::OutEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        todo!()
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        event: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        self.b.inject_event(peer_id, connection, event)
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NBAction<Self::OutEvent, Self::ProtocolsHandler>> {
        let poll = self.b.poll(cx, params);
        if let Poll::Ready(ev) = &poll {
            match ev {
                NBAction::DialPeer {
                    peer_id,
                    condition,
                    handler,
                } => {
                    // NOTE: I don't think there is any guarantee that this condition will be the
                    // same when the swarm gets this event as right now.
                    // This will get ugly
                    match condition {
                        DialPeerCondition::Disconnected => {
                            // TODO: if the peer does not exist, register it as disconnected with
                            // dialing attempts since the condition is met.
                        }
                        DialPeerCondition::NotDialing => {
                            // TODO: asumming that this requires an active dial attempt to this
                            // peer and not a multiaddr, check if the peer has dialing attempts. If
                            // not, the condition is met and then we register the attempt.
                            // Peer would get registered as disconnected if it does not exist.
                        }
                        DialPeerCondition::Always => {
                            // TODO: registed the dial attempt.  Peer would get registered as
                            // disconnected if it does not exist.
                        }
                    }
                }
                NBAction::CloseConnection {
                    peer_id,
                    connection,
                } => match connection {
                    CloseConnection::One(_) => {
                        // TODO: add the connection_id to the disconnections.
                    }
                    CloseConnection::All => {
                        // TODO: add all the connection_ids to the disconnections.
                    }
                },
                NBAction::GenerateEvent(_)
                | NBAction::DialAddress { .. }
                | NBAction::NotifyHandler { .. }
                | NBAction::ReportObservedAddr { .. } => {}
            }
        }
        poll
    }
}

/* utilities */

// Simply to make some code shorter
struct Node {
    swarm: Swarm<Behaviour>,
}
impl std::ops::Deref for Node {
    type Target = Swarm<Behaviour>;

    fn deref(&self) -> &Self::Target {
        &self.swarm
    }
}
impl std::ops::DerefMut for Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.swarm
    }
}

impl Node {
    pub fn queue_event(&mut self, ev: PuppetEvent) {
        self.swarm.behaviour_mut().puppet.queue_event(ev)
    }

    pub fn calls(&self) -> &HashMap<MethodCall, usize> {
        self.swarm.behaviour().puppet.calls()
    }

    // pub fn peer_manager(&mut self) -> &mut PeerManager<E> {
    // &mut self.swarm.behaviour_mut().peer_manager
    // }
}

impl From<()> for Event {
    fn from(_: ()) -> Self {
        unreachable!("Puppet Behaviour does not emit events")
    }
}

async fn build_swarm(_log: slog::Logger) -> Node {
    let local_key = libp2p::identity::Keypair::generate_secp256k1();
    let local_peer_id = PeerId::from(local_key.public());

    // Build the swarm
    let swarm = {
        let transport = development_transport(local_key)
            .await
            .expect("builds dev transport");

        let behaviour = Behaviour {
            puppet: Default::default(),
            conn_tracker: ConnTracker {
                peers: Arc::new(RwLock::new(HashMap::new())),
            },
        };
        Swarm::new(transport, behaviour, local_peer_id)
    };
    Node { swarm }
}

async fn build_dummy_swarm() -> Swarm<DummyBehaviour> {
    let local_key = libp2p::identity::Keypair::generate_secp256k1();
    let local_peer_id = PeerId::from(local_key.public());
    let transport = development_transport(local_key)
        .await
        .expect("builds dev transport");
    let behaviour = DummyBehaviour::with_keep_alive(libp2p::swarm::KeepAlive::Yes);
    Swarm::new(transport, behaviour, local_peer_id)
}

#[tokio::test]
async fn basic_test() {
    let log = common::build_log(slog::Level::Trace, true);

    // Build the connection tracker node and bind a listener
    let mut node = build_swarm(log.new(o!("node" => "puppet"))).await;
    let _our_addr = common::behaviours::bind_listener(&mut node).await;

    // Build the dummy swarm and bind a listener
    let mut dummy = build_dummy_swarm().await;
    let dummy_addr = common::behaviours::bind_listener(&mut dummy).await;
    let dummy_peer_id = *dummy.local_peer_id();

    // Dial dummy from a sibling behaviour
    node.queue_event(NBAction::DialAddress {
        address: dummy_addr,
        handler: DummyProtocolsHandler {
            keep_alive: libp2p::swarm::KeepAlive::Yes,
        },
    });
    let dc_time = tokio::time::sleep(tokio::time::Duration::from_secs(5));
    let run_duration = tokio::time::sleep(tokio::time::Duration::from_secs(10));
    futures::pin_mut!(dc_time);
    futures::pin_mut!(run_duration);
    loop {
        tokio::select! {
            ev = node.select_next_some() => {
                debug!(log, "Swarm event"; "ev" => ?ev);
            }
            ev = dummy.select_next_some() => {
                debug!(log, "Dummy swarm event"; "ev" => ?ev);
            }
            _ = run_duration.as_mut() => {
                debug!(log, "Method calls"; "calls" => ?node.calls());
                return;
            }
            _ = dc_time.as_mut() => {
                node.queue_event(NBAction::CloseConnection{ peer_id: dummy_peer_id, connection: CloseConnection::All});
            }
        }
    }
}
