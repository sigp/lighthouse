use crate::error;
use crate::message_handler::{HandlerMessage, MessageHandler};
use crate::messages::{NetworkMessage, NodeMessage};
use crate::NetworkConfig;
use crossbeam_channel::{unbounded as channel, Sender, TryRecvError};
use futures::future::lazy;
use futures::future::poll_fn;
use futures::prelude::*;
use futures::sync::oneshot;
use futures::Stream;
use libp2p::behaviour::BehaviourEvent;
use libp2p::error::Error as libp2pError;
use libp2p::Service as LibP2PService;
use libp2p::{Libp2pEvent, PeerId};
use slog::{debug, info, o, trace, warn, Logger};
use std::sync::{Arc, Mutex};
use tokio::runtime::TaskExecutor;
use client::ClientTypes;

/// Service that handles communication between internal services and the libp2p network service.
pub struct Service<T: ClientTypes> {
    //libp2p_service: Arc<Mutex<LibP2PService>>,
    libp2p_exit: oneshot::Sender<()>,
    network_send: crossbeam_channel::Sender<NetworkMessage>,
    //message_handler: MessageHandler,
    //message_handler_send: Sender<HandlerMessage>,
    PhantomData: T,
}

impl<T: ClientTypes> Service<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T::DB, T::SlotClock, T::ForkChoice>,
        config: &NetworkConfig,
        executor: &TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<(Arc<Self>, Sender<NetworkMessage>)> {
        // launch message handler thread
        let message_handler_log = log.new(o!("Service" => "MessageHandler"));
        let message_handler_send = MessageHandler::new(beacon_chain, executor, message_handler_log)?;

        // launch libp2p service
        let libp2p_log = log.new(o!("Service" => "Libp2p"));
        let libp2p_service = LibP2PService::new(config, libp2p_log)?;

        // TODO: Spawn thread to handle libp2p messages and pass to message handler thread.
        let (network_send, libp2p_exit) =
            spawn_service(libp2p_service, message_handler_send, executor, log)?;
        let network = Service {
            libp2p_exit,
            network_send: network_send.clone(),
        };

        Ok((Arc::new(network), network_send))
    }

    // TODO: Testing only
    pub fn send_message(&self, message: String) {
        let node_message = NodeMessage::Message(message);
        self.network_send
            .send(NetworkMessage::Send(PeerId::random(), node_message));
    }
}

fn spawn_service(
    libp2p_service: LibP2PService,
    message_handler_send: crossbeam_channel::Sender<HandlerMessage>,
    executor: &TaskExecutor,
    log: slog::Logger,
) -> error::Result<(
    crossbeam_channel::Sender<NetworkMessage>,
    oneshot::Sender<()>,
)> {
    let (network_exit, exit_rx) = oneshot::channel();
    let (network_send, network_recv) = channel::<NetworkMessage>();

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
            debug!(log.clone(), "Network service ended");
            Ok(())
        }),
    );

    Ok((network_send, network_exit))
}

fn network_service(
    mut libp2p_service: LibP2PService,
    network_recv: crossbeam_channel::Receiver<NetworkMessage>,
    message_handler_send: crossbeam_channel::Sender<HandlerMessage>,
    log: slog::Logger,
) -> impl futures::Future<Item = (), Error = libp2p::error::Error> {
    futures::future::poll_fn(move || -> Result<_, libp2p::error::Error> {
        // poll the swarm
        loop {
            match libp2p_service.poll() {
                Ok(Async::Ready(Some(Libp2pEvent::RPC(rpc_event)))) => {
                    debug!(
                        libp2p_service.log,
                        "RPC Event: Rpc message received: {:?}", rpc_event
                    );
                    message_handler_send
                        .send(HandlerMessage::RPC(rpc_event))
                        .map_err(|_| "failed to send rpc to handler");
                }
                Ok(Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id)))) => {
                    debug!(libp2p_service.log, "Peer Dialed: {:?}", peer_id);
                    message_handler_send
                        .send(HandlerMessage::PeerDialed(peer_id))
                        .map_err(|_| "failed to send rpc to handler");
                }
                Ok(Async::Ready(Some(Libp2pEvent::Message(m)))) => debug!(
                    libp2p_service.log,
                    "Network Service: Message received: {}", m
                ),
                _ => break,
            }
        }
        // poll the network channel
        // TODO: refactor - combine poll_fn's?
        loop {
            match network_recv.try_recv() {
                // TODO: Testing message - remove
                Ok(NetworkMessage::Send(_peer_id, node_message)) => {
                    match node_message {
                        NodeMessage::Message(m) => {
                            debug!(log, "Message received via network channel: {:?}", m);
                            //TODO: Make swarm private
                            //TODO: Implement correct peer id topic message handling
                            libp2p_service.swarm.send_message(m);
                        }
                        //TODO: Handle all NodeMessage types
                        _ => break,
                    };
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(libp2p::error::Error::from("Network channel disconnected"));
                }
                // TODO: Implement all NetworkMessage
                _ => break,
            }
        }
        Ok(Async::NotReady)
    })
}
