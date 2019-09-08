use crate::error;
use crate::message_handler::{HandlerMessage, MessageHandler};
use crate::NetworkConfig;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use core::marker::PhantomData;
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::Topic;
use eth2_libp2p::{Enr, Libp2pEvent, Multiaddr, PeerId, Swarm};
use eth2_libp2p::{PubsubMessage, RPCEvent};
use futures::prelude::*;
use futures::Stream;
use parking_lot::Mutex;
use slog::{debug, info, o, trace};
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use tokio::sync::{mpsc, oneshot};

/// Service that handles communication between internal services and the eth2_libp2p network service.
pub struct Service<T: BeaconChainTypes> {
    libp2p_service: Arc<Mutex<LibP2PService>>,
    libp2p_port: u16,
    _libp2p_exit: oneshot::Sender<()>,
    _network_send: mpsc::UnboundedSender<NetworkMessage>,
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes + 'static> Service<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        executor: &TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<(Arc<Self>, mpsc::UnboundedSender<NetworkMessage>)> {
        // build the network channel
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage>();
        // launch message handler thread
        let message_handler_send =
            MessageHandler::spawn(beacon_chain, network_send.clone(), executor, log.clone())?;

        let network_log = log.new(o!("Service" => "Network"));
        // launch libp2p service
        let libp2p_service = Arc::new(Mutex::new(LibP2PService::new(
            config.clone(),
            network_log.clone(),
        )?));

        let libp2p_exit = spawn_service(
            libp2p_service.clone(),
            network_recv,
            message_handler_send,
            executor,
            network_log,
        )?;
        let network_service = Service {
            libp2p_service,
            libp2p_port: config.libp2p_port,
            _libp2p_exit: libp2p_exit,
            _network_send: network_send.clone(),
            _phantom: PhantomData,
        };

        Ok((Arc::new(network_service), network_send))
    }

    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Enr {
        self.libp2p_service
            .lock()
            .swarm
            .discovery()
            .local_enr()
            .clone()
    }

    /// Returns the local libp2p PeerID.
    pub fn local_peer_id(&self) -> PeerId {
        self.libp2p_service.lock().local_peer_id.clone()
    }

    /// Returns the list of `Multiaddr` that the underlying libp2p instance is listening on.
    pub fn listen_multiaddrs(&self) -> Vec<Multiaddr> {
        Swarm::listeners(&self.libp2p_service.lock().swarm)
            .cloned()
            .collect()
    }

    /// Returns the libp2p port that this node has been configured to listen using.
    pub fn listen_port(&self) -> u16 {
        self.libp2p_port
    }

    /// Returns the number of libp2p connected peers.
    pub fn connected_peers(&self) -> usize {
        self.libp2p_service.lock().swarm.connected_peers()
    }

    /// Returns the set of `PeerId` that are connected via libp2p.
    pub fn connected_peer_set(&self) -> Vec<PeerId> {
        self.libp2p_service
            .lock()
            .swarm
            .discovery()
            .connected_peer_set()
            .iter()
            .cloned()
            .collect()
    }

    /// Provides a reference to the underlying libp2p service.
    pub fn libp2p_service(&self) -> Arc<Mutex<LibP2PService>> {
        self.libp2p_service.clone()
    }
}

fn spawn_service(
    libp2p_service: Arc<Mutex<LibP2PService>>,
    network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
    message_handler_send: mpsc::UnboundedSender<HandlerMessage>,
    executor: &TaskExecutor,
    log: slog::Logger,
) -> error::Result<tokio::sync::oneshot::Sender<()>> {
    let (network_exit, exit_rx) = tokio::sync::oneshot::channel();

    // spawn on the current executor
    executor.spawn(
        network_service(
            libp2p_service,
            network_recv,
            message_handler_send,
            log.clone(),
        )
        // allow for manual termination
        .select(exit_rx.then(|_| Ok(())))
        .then(move |_| {
            info!(log.clone(), "Network service shutdown");
            Ok(())
        }),
    );

    Ok(network_exit)
}

//TODO: Potentially handle channel errors
fn network_service(
    libp2p_service: Arc<Mutex<LibP2PService>>,
    mut network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
    mut message_handler_send: mpsc::UnboundedSender<HandlerMessage>,
    log: slog::Logger,
) -> impl futures::Future<Item = (), Error = eth2_libp2p::error::Error> {
    futures::future::poll_fn(move || -> Result<_, eth2_libp2p::error::Error> {
        // if the network channel is not ready, try the swarm
        loop {
            // poll the network channel
            match network_recv.poll() {
                Ok(Async::Ready(Some(message))) => match message {
                    NetworkMessage::RPC(peer_id, rpc_event) => {
                        trace!(log, "{}", rpc_event);
                        libp2p_service.lock().swarm.send_rpc(peer_id, rpc_event);
                    }
                    NetworkMessage::Propagate {
                        propagation_source,
                        message_id,
                    } => {
                        trace!(log, "Propagating gossipsub message";
                        "propagation_peer" => format!("{:?}", propagation_source),
                        "message_id" => format!("{}", message_id),
                        );
                        libp2p_service
                            .lock()
                            .swarm
                            .propagate_message(&propagation_source, message_id);
                    }
                    NetworkMessage::Publish { topics, message } => {
                        debug!(log, "Sending pubsub message"; "topics" => format!("{:?}",topics));
                        libp2p_service.lock().swarm.publish(&topics, message);
                    }
                },
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => {
                    return Err(eth2_libp2p::error::Error::from("Network channel closed"));
                }
                Err(_) => {
                    return Err(eth2_libp2p::error::Error::from("Network channel error"));
                }
            }
        }

        loop {
            // poll the swarm
            match libp2p_service.lock().poll() {
                Ok(Async::Ready(Some(event))) => match event {
                    Libp2pEvent::RPC(peer_id, rpc_event) => {
                        trace!(log, "{}", rpc_event);
                        message_handler_send
                            .try_send(HandlerMessage::RPC(peer_id, rpc_event))
                            .map_err(|_| "Failed to send RPC to handler")?;
                    }
                    Libp2pEvent::PeerDialed(peer_id) => {
                        debug!(log, "Peer Dialed"; "PeerID" => format!("{:?}", peer_id));
                        message_handler_send
                            .try_send(HandlerMessage::PeerDialed(peer_id))
                            .map_err(|_| "Failed to send PeerDialed to handler")?;
                    }
                    Libp2pEvent::PeerDisconnected(peer_id) => {
                        debug!(log, "Peer Disconnected";  "PeerID" => format!("{:?}", peer_id));
                        message_handler_send
                            .try_send(HandlerMessage::PeerDisconnected(peer_id))
                            .map_err(|_| "Failed to send PeerDisconnected to handler")?;
                    }
                    Libp2pEvent::PubsubMessage {
                        id,
                        source,
                        message,
                        ..
                    } => {
                        message_handler_send
                            .try_send(HandlerMessage::PubsubMessage(id, source, message))
                            .map_err(|_| "Failed to send pubsub message to handler")?;
                    }
                },
                Ok(Async::Ready(None)) => unreachable!("Stream never ends"),
                Ok(Async::NotReady) => break,
                Err(_) => break,
            }
        }

        Ok(Async::NotReady)
    })
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
    /// Propagate a received gossipsub message
    Propagate {
        propagation_source: PeerId,
        message_id: String,
    },
}
