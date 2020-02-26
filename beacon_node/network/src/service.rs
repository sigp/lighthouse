use crate::error;
use crate::message_handler::{HandlerMessage, MessageHandler};
use crate::persisted_dht::{load_dht, persist_dht};
use crate::NetworkConfig;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use core::marker::PhantomData;
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::{
    rpc::RPCRequest, Enr, Libp2pEvent, MessageId, Multiaddr, NetworkGlobals, PeerId, Swarm, Topic,
};
use eth2_libp2p::{PubsubMessage, RPCEvent};
use futures::prelude::*;
use futures::Stream;
use slog::{debug, error, info, trace};
use std::collections::HashSet;
use std::sync::{atomic::Ordering, Arc};
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use tokio::timer::Delay;

mod tests;

/// The time in seconds that a peer will be banned and prevented from reconnecting.
const BAN_PEER_TIMEOUT: u64 = 30;

/// Service that handles communication between internal services and the `eth2_libp2p` network service.
pub struct Service<T: BeaconChainTypes> {
    libp2p_port: u16,
    network_globals: Arc<NetworkGlobals>,
    _libp2p_exit: oneshot::Sender<()>,
    _network_send: mpsc::UnboundedSender<NetworkMessage>,
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes> Service<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        executor: &TaskExecutor,
        network_log: slog::Logger,
    ) -> error::Result<(Arc<Self>, mpsc::UnboundedSender<NetworkMessage>)> {
        // build the network channel
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage>();
        // launch message handler thread
        let store = beacon_chain.store.clone();
        let message_handler_send = MessageHandler::spawn(
            beacon_chain,
            network_send.clone(),
            executor,
            network_log.clone(),
        )?;

        let propagation_percentage = config.propagation_percentage;
        // launch libp2p service
        let (network_globals, mut libp2p_service) =
            LibP2PService::new(config, network_log.clone())?;

        for enr in load_dht::<T>(store.clone()) {
            libp2p_service.swarm.add_enr(enr);
        }

        // A delay used to initialise code after the network has started
        // This is currently used to obtain the listening addresses from the libp2p service.
        let initial_delay = Delay::new(Instant::now() + Duration::from_secs(1));

        let libp2p_exit = spawn_service::<T>(
            libp2p_service,
            network_recv,
            message_handler_send,
            executor,
            store,
            network_globals.clone(),
            initial_delay,
            network_log.clone(),
            propagation_percentage,
        )?;

        let network_service = Service {
            libp2p_port: config.libp2p_port,
            network_globals,
            _libp2p_exit: libp2p_exit,
            _network_send: network_send.clone(),
            _phantom: PhantomData,
        };

        Ok((Arc::new(network_service), network_send))
    }

    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Option<Enr> {
        self.network_globals.local_enr.read().clone()
    }

    /// Returns the local libp2p PeerID.
    pub fn local_peer_id(&self) -> PeerId {
        self.network_globals.peer_id.read().clone()
    }

    /// Returns the list of `Multiaddr` that the underlying libp2p instance is listening on.
    pub fn listen_multiaddrs(&self) -> Vec<Multiaddr> {
        self.network_globals.listen_multiaddrs.read().clone()
    }

    /// Returns the libp2p port that this node has been configured to listen using.
    pub fn listen_port(&self) -> u16 {
        self.libp2p_port
    }

    /// Returns the number of libp2p connected peers.
    pub fn connected_peers(&self) -> usize {
        self.network_globals.connected_peers.load(Ordering::Relaxed)
    }

    /// Returns the set of `PeerId` that are connected via libp2p.
    pub fn connected_peer_set(&self) -> HashSet<PeerId> {
        self.network_globals.connected_peer_set.read().clone()
    }
}

fn spawn_service<T: BeaconChainTypes>(
    mut libp2p_service: LibP2PService,
    mut network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
    mut message_handler_send: mpsc::UnboundedSender<HandlerMessage>,
    executor: &TaskExecutor,
    store: Arc<T::Store>,
    network_globals: Arc<NetworkGlobals>,
    mut initial_delay: Delay,
    log: slog::Logger,
    propagation_percentage: Option<u8>,
) -> error::Result<tokio::sync::oneshot::Sender<()>> {
    let (network_exit, mut exit_rx) = tokio::sync::oneshot::channel();

    // spawn on the current executor
    executor.spawn(
    futures::future::poll_fn(move || -> Result<_, ()> {


        if !initial_delay.is_elapsed() {
            if let Ok(Async::Ready(_)) = initial_delay.poll() {
                        let multi_addrs = Swarm::listeners(&libp2p_service.swarm).cloned().collect();
                        *network_globals.listen_multiaddrs.write() = multi_addrs;
            }
        }

        // perform termination tasks when the network is being shutdown
        if let Ok(Async::Ready(_)) | Err(_) = exit_rx.poll() {
                    // network thread is terminating
                    let enrs: Vec<Enr> = libp2p_service.swarm.enr_entries().cloned().collect();
                    debug!(
                        log,
                        "Persisting DHT to store";
                        "Number of peers" => format!("{}", enrs.len()),
                    );

                    match persist_dht::<T>(store.clone(), enrs) {
                        Err(e) => error!(
                            log,
                            "Failed to persist DHT on drop";
                            "error" => format!("{:?}", e)
                        ),
                        Ok(_) => info!(
                            log,
                            "Saved DHT state";
                        ),
                    }

                    info!(log.clone(), "Network service shutdown");
                    return Ok(Async::Ready(()));
        }

        // processes the network channel before processing the libp2p swarm
        loop {
            // poll the network channel
            match network_recv.poll() {
                Ok(Async::Ready(Some(message))) => match message {
                    NetworkMessage::RPC(peer_id, rpc_event) => {
                        trace!(log, "Sending RPC"; "rpc" => format!("{}", rpc_event));
                        libp2p_service.swarm.send_rpc(peer_id, rpc_event);
                    }
                    NetworkMessage::Propagate {
                        propagation_source,
                        message_id,
                    } => {
                        // TODO: Remove this for mainnet
                        // randomly prevents propagation
                        let mut should_send = true;
                        if let Some(percentage) = propagation_percentage {
                            // not exact percentage but close enough
                            let rand = rand::random::<u8>() % 100;
                            if rand > percentage {
                                // don't propagate
                                should_send = false;
                            }
                        }
                        if !should_send {
                            info!(log, "Random filter did not propagate message");
                        } else {
                            trace!(log, "Propagating gossipsub message";
                            "propagation_peer" => format!("{:?}", propagation_source),
                            "message_id" => message_id.to_string(),
                            );
                            libp2p_service
                                .swarm
                                .propagate_message(&propagation_source, message_id);
                        }
                    }
                    NetworkMessage::Publish { topics, message } => {
                        // TODO: Remove this for mainnet
                        // randomly prevents propagation
                        let mut should_send = true;
                        if let Some(percentage) = propagation_percentage {
                            // not exact percentage but close enough
                            let rand = rand::random::<u8>() % 100;
                            if rand > percentage {
                                // don't propagate
                                should_send = false;
                            }
                        }
                        if !should_send {
                            info!(log, "Random filter did not publish message");
                        } else {
                            debug!(log, "Sending pubsub message"; "topics" => format!("{:?}",topics));
                            libp2p_service.swarm.publish(&topics, message);
                        }
                    }
                    NetworkMessage::Disconnect { peer_id } => {
                        libp2p_service.disconnect_and_ban_peer(
                            peer_id,
                            std::time::Duration::from_secs(BAN_PEER_TIMEOUT),
                        );
                    }
                },
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => {
                    debug!(log, "Network channel closed");
                    return Err(());
                }
                Err(e) => {
                    debug!(log, "Network channel error"; "error" => format!("{}", e));
                    return Err(());
                }
            }
        }

        let mut peers_to_ban = Vec::new();
        // poll the swarm
        loop {
            match libp2p_service.poll() {
                Ok(Async::Ready(Some(event))) => match event {
                    Libp2pEvent::RPC(peer_id, rpc_event) => {
                        // trace!(log, "Received RPC"; "rpc" => format!("{}", rpc_event));

                        // if we received a Goodbye message, drop and ban the peer
                        if let RPCEvent::Request(_, RPCRequest::Goodbye(_)) = rpc_event {
                            peers_to_ban.push(peer_id.clone());
                        };
                        message_handler_send
                            .try_send(HandlerMessage::RPC(peer_id, rpc_event))
                            .map_err(|_| { debug!(log, "Failed to send RPC to handler");} )?;
                    }
                    Libp2pEvent::PeerDialed(peer_id) => {
                        debug!(log, "Peer Dialed"; "peer_id" => format!("{:?}", peer_id));
                        message_handler_send
                            .try_send(HandlerMessage::PeerDialed(peer_id))
                            .map_err(|_| { debug!(log, "Failed to send peer dialed to handler");})?;
                    }
                    Libp2pEvent::PeerDisconnected(peer_id) => {
                        debug!(log, "Peer Disconnected";  "peer_id" => format!("{:?}", peer_id));
                        message_handler_send
                            .try_send(HandlerMessage::PeerDisconnected(peer_id))
                            .map_err(|_| { debug!(log, "Failed to send peer disconnect to handler");})?;
                    }
                    Libp2pEvent::PubsubMessage {
                        id,
                        source,
                        message,
                        ..
                    } => {
                        message_handler_send
                            .try_send(HandlerMessage::PubsubMessage(id, source, message))
                            .map_err(|_| { debug!(log, "Failed to send pubsub message to handler");})?;
                    }
                    Libp2pEvent::PeerSubscribed(_, _) => {}
                },
                Ok(Async::Ready(None)) => unreachable!("Stream never ends"),
                Ok(Async::NotReady) => break,
                Err(_) => break,
            }
        }

        // ban and disconnect any peers that sent Goodbye requests
        while let Some(peer_id) = peers_to_ban.pop() {
            libp2p_service.disconnect_and_ban_peer(
                peer_id.clone(),
                std::time::Duration::from_secs(BAN_PEER_TIMEOUT),
            );
        }

        Ok(Async::NotReady)
    })

    );

    Ok(network_exit)
}

/// Types of messages that the network service can receive.
#[derive(Debug)]
pub enum NetworkMessage {
    /// Send an RPC message to the libp2p service.
    RPC(PeerId, RPCEvent),
    /// Publish a message to gossipsub.
    Publish {
        topics: Vec<Topic>,
        message: PubsubMessage,
    },
    /// Propagate a received gossipsub message.
    Propagate {
        propagation_source: PeerId,
        message_id: MessageId,
    },
    /// Disconnect and bans a peer id.
    Disconnect { peer_id: PeerId },
}
