use crate::error;
use crate::message_handler::{HandlerMessage, MessageHandler};
use crate::NetworkConfig;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::Topic;
use eth2_libp2p::{Libp2pEvent, PeerId};
use eth2_libp2p::{PubsubMessage, RPCEvent};
use futures::prelude::*;
use futures::Stream;
use slog::{debug, info, o, trace};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use tokio::sync::{mpsc, oneshot};

/// Service that handles communication between internal services and the eth2_libp2p network service.
pub struct Service<T: BeaconChainTypes> {
    //libp2p_service: Arc<Mutex<LibP2PService>>,
    _libp2p_exit: oneshot::Sender<()>,
    network_send: mpsc::UnboundedSender<NetworkMessage>,
    _phantom: PhantomData<T>, //message_handler: MessageHandler,
                              //message_handler_send: Sender<HandlerMessage>
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
        let message_handler_log = log.new(o!("Service" => "MessageHandler"));
        let message_handler_send = MessageHandler::spawn(
            beacon_chain,
            network_send.clone(),
            executor,
            message_handler_log,
        )?;

        // launch libp2p service
        let libp2p_log = log.new(o!("Service" => "Libp2p"));
        let libp2p_service = LibP2PService::new(config.clone(), libp2p_log)?;

        // TODO: Spawn thread to handle libp2p messages and pass to message handler thread.
        let libp2p_exit = spawn_service(
            libp2p_service,
            network_recv,
            message_handler_send,
            executor,
            log,
        )?;
        let network_service = Service {
            _libp2p_exit: libp2p_exit,
            network_send: network_send.clone(),
            _phantom: PhantomData,
        };

        Ok((Arc::new(network_service), network_send))
    }

    // TODO: Testing only
    pub fn send_message(&mut self) {
        self.network_send
            .try_send(NetworkMessage::Send(
                PeerId::random(),
                OutgoingMessage::NotifierTest,
            ))
            .unwrap();
    }
}

fn spawn_service(
    libp2p_service: LibP2PService,
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
    mut libp2p_service: LibP2PService,
    mut network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
    mut message_handler_send: mpsc::UnboundedSender<HandlerMessage>,
    log: slog::Logger,
) -> impl futures::Future<Item = (), Error = eth2_libp2p::error::Error> {
    futures::future::poll_fn(move || -> Result<_, eth2_libp2p::error::Error> {
        // only end the loop once both major polls are not ready.
        let mut not_ready_count = 0;
        while not_ready_count < 2 {
            not_ready_count = 0;
            // poll the network channel
            match network_recv.poll() {
                Ok(Async::Ready(Some(message))) => {
                    match message {
                        // TODO: Testing message - remove
                        NetworkMessage::Send(peer_id, outgoing_message) => {
                            match outgoing_message {
                                OutgoingMessage::RPC(rpc_event) => {
                                    trace!(log, "Sending RPC Event: {:?}", rpc_event);
                                    //TODO: Make swarm private
                                    //TODO: Implement correct peer id topic message handling
                                    libp2p_service.swarm.send_rpc(peer_id, rpc_event);
                                }
                                OutgoingMessage::NotifierTest => {
                                    // debug!(log, "Received message from notifier");
                                }
                            };
                        }
                        NetworkMessage::Publish { topics, message } => {
                            debug!(log, "Sending pubsub message"; "topics" => format!("{:?}",topics));
                            libp2p_service.swarm.publish(topics, *message);
                        }
                    }
                }
                Ok(Async::NotReady) => not_ready_count += 1,
                Ok(Async::Ready(None)) => {
                    return Err(eth2_libp2p::error::Error::from("Network channel closed"));
                }
                Err(_) => {
                    return Err(eth2_libp2p::error::Error::from("Network channel error"));
                }
            }

            // poll the swarm
            match libp2p_service.poll() {
                Ok(Async::Ready(Some(event))) => match event {
                    Libp2pEvent::RPC(peer_id, rpc_event) => {
                        trace!(log, "RPC Event: RPC message received: {:?}", rpc_event);
                        message_handler_send
                            .try_send(HandlerMessage::RPC(peer_id, rpc_event))
                            .map_err(|_| "failed to send rpc to handler")?;
                    }
                    Libp2pEvent::PeerDialed(peer_id) => {
                        debug!(log, "Peer Dialed: {:?}", peer_id);
                        message_handler_send
                            .try_send(HandlerMessage::PeerDialed(peer_id))
                            .map_err(|_| "failed to send rpc to handler")?;
                    }
                    Libp2pEvent::PubsubMessage {
                        source, message, ..
                    } => {
                        //TODO: Decide if we need to propagate the topic upwards. (Potentially for
                        //attestations)
                        message_handler_send
                            .try_send(HandlerMessage::PubsubMessage(source, message))
                            .map_err(|_| " failed to send pubsub message to handler")?;
                    }
                },
                Ok(Async::Ready(None)) => unreachable!("Stream never ends"),
                Ok(Async::NotReady) => not_ready_count += 1,
                Err(_) => not_ready_count += 1,
            }
        }
        Ok(Async::NotReady)
    })
}

/// Types of messages that the network service can receive.
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    /// Send a message to libp2p service.
    //TODO: Define typing for messages across the wire
    Send(PeerId, OutgoingMessage),
    /// Publish a message to pubsub mechanism.
    Publish {
        topics: Vec<Topic>,
        message: Box<PubsubMessage>,
    },
}

/// Type of outgoing messages that can be sent through the network service.
#[derive(Debug, Clone)]
pub enum OutgoingMessage {
    /// Send an RPC request/response.
    RPC(RPCEvent),
    //TODO: Remove
    NotifierTest,
}
