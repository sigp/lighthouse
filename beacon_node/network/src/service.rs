use crate::error;
use crate::persisted_dht::{load_dht, persist_dht};
use crate::router::{Router, RouterMessage};
use crate::{
    attestation_service::{AttServiceMessage, AttestationService},
    NetworkConfig,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::{rpc::RPCRequest, Enr, Libp2pEvent, MessageId, NetworkGlobals, PeerId, Swarm};
use eth2_libp2p::{PubsubMessage, RPCEvent};
use futures::prelude::*;
use futures::Stream;
use rest_types::ValidatorSubscription;
use slog::{debug, error, info, trace};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use tokio::timer::Delay;
use types::EthSpec;

mod tests;

/// The time in seconds that a peer will be banned and prevented from reconnecting.
const BAN_PEER_TIMEOUT: u64 = 30;

/// Service that handles communication between internal services and the `eth2_libp2p` network service.
pub struct NetworkService<T: BeaconChainTypes> {
    /// The underlying libp2p service that drives all the network interactions.
    libp2p: LibP2PService<T::EthSpec>,
    /// An attestation and subnet manager service.
    attestation_service: AttestationService<T>,
    /// The receiver channel for lighthouse to communicate with the network service.
    network_recv: mpsc::UnboundedReceiver<NetworkMessage<T::EthSpec>>,
    /// The sending channel for the network service to send messages to be routed throughout
    /// lighthouse.
    router_send: mpsc::UnboundedSender<RouterMessage<T::EthSpec>>,
    /// A reference to lighthouse's database to persist the DHT.
    store: Arc<T::Store>,
    /// A collection of global variables, accessible outside of the network service.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    /// An initial delay to update variables after the libp2p service has started.
    initial_delay: Delay,
    /// The logger for the network service.
    log: slog::Logger,
    /// A probability of propagation.
    propagation_percentage: Option<u8>,
}

impl<T: BeaconChainTypes> NetworkService<T> {
    pub fn start(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        executor: &TaskExecutor,
        network_log: slog::Logger,
    ) -> error::Result<(
        Arc<NetworkGlobals<T::EthSpec>>,
        mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        oneshot::Sender<()>,
    )> {
        // build the network channel
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage<T::EthSpec>>();
        // Get a reference to the beacon chain store
        let store = beacon_chain.store.clone();
        // launch the router task
        let router_send = Router::spawn(
            beacon_chain.clone(),
            network_send.clone(),
            executor,
            network_log.clone(),
        )?;

        let propagation_percentage = config.propagation_percentage;
        // launch libp2p service
        let (network_globals, mut libp2p) = LibP2PService::new(config, network_log.clone())?;

        for enr in load_dht::<T::Store, T::EthSpec>(store.clone()) {
            libp2p.swarm.add_enr(enr);
        }

        // A delay used to initialise code after the network has started
        // This is currently used to obtain the listening addresses from the libp2p service.
        let initial_delay = Delay::new(Instant::now() + Duration::from_secs(1));

        // create the attestation service
        let attestation_service =
            AttestationService::new(beacon_chain, network_globals.clone(), &network_log);

        // create the network service and spawn the task
        let network_service = NetworkService {
            libp2p,
            attestation_service,
            network_recv,
            router_send,
            store,
            network_globals: network_globals.clone(),
            initial_delay,
            log: network_log,
            propagation_percentage,
        };

        let network_exit = spawn_service(network_service, &executor)?;

        Ok((network_globals, network_send, network_exit))
    }
}

fn spawn_service<T: BeaconChainTypes>(
    mut service: NetworkService<T>,
    executor: &TaskExecutor,
) -> error::Result<tokio::sync::oneshot::Sender<()>> {
    let (network_exit, mut exit_rx) = tokio::sync::oneshot::channel();

    // spawn on the current executor
    executor.spawn(
    futures::future::poll_fn(move || -> Result<_, ()> {

        let log = &service.log;

        if !service.initial_delay.is_elapsed() {
            if let Ok(Async::Ready(_)) = service.initial_delay.poll() {
                        let multi_addrs = Swarm::listeners(&service.libp2p.swarm).cloned().collect();
                        *service.network_globals.listen_multiaddrs.write() = multi_addrs;
            }
        }

        // perform termination tasks when the network is being shutdown
        if let Ok(Async::Ready(_)) | Err(_) = exit_rx.poll() {
                    // network thread is terminating
                    let enrs: Vec<Enr> = service.libp2p.swarm.enr_entries().cloned().collect();
                    debug!(
                        log,
                        "Persisting DHT to store";
                        "Number of peers" => format!("{}", enrs.len()),
                    );

                    match persist_dht::<T::Store, T::EthSpec>(service.store.clone(), enrs) {
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
            match service.network_recv.poll() {
                Ok(Async::Ready(Some(message))) => match message {
                    NetworkMessage::RPC(peer_id, rpc_event) => {
                        trace!(log, "Sending RPC"; "rpc" => format!("{}", rpc_event));
                        service.libp2p.swarm.send_rpc(peer_id, rpc_event);
                    }
                    NetworkMessage::Propagate {
                        propagation_source,
                        message_id,
                    } => {
                        // TODO: Remove this for mainnet
                        // randomly prevents propagation
                        let mut should_send = true;
                        if let Some(percentage) = service.propagation_percentage {
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
                            service.libp2p
                                .swarm
                                .propagate_message(&propagation_source, message_id);
                        }
                    }
                    NetworkMessage::Publish { messages } => {
                        // TODO: Remove this for mainnet
                        // randomly prevents propagation
                        let mut should_send = true;
                        if let Some(percentage) = service.propagation_percentage {
                            // not exact percentage but close enough
                            let rand = rand::random::<u8>() % 100;
                            if rand > percentage {
                                // don't propagate
                                should_send = false;
                            }
                        }
                        if !should_send {
                            info!(log, "Random filter did not publish messages");
                        } else {
                            let mut unique_topics = Vec::new();
                            for message in &messages {
                                for topic in message.topics() {
                                    if !unique_topics.contains(&topic) {
                                        unique_topics.push(topic);
                                    }
                                }
                            }
                            debug!(log, "Sending pubsub messages"; "count" => messages.len(), "topics" => format!("{:?}", unique_topics));
                            service.libp2p.swarm.publish(messages);
                        }
                    }
                    NetworkMessage::Disconnect { peer_id } => {
                        service.libp2p.disconnect_and_ban_peer(
                            peer_id,
                            std::time::Duration::from_secs(BAN_PEER_TIMEOUT),
                        );
                    }
                    NetworkMessage::Subscribe { subscriptions } =>
                    {
                       // the result is dropped as it used solely for ergonomics
                       let _ = service.attestation_service.validator_subscriptions(subscriptions);
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

        // process any attestation service events
        // NOTE: This must come after the network message processing as that may trigger events in
        // the attestation service.
        while let Ok(Async::Ready(Some(attestation_service_message))) = service.attestation_service.poll() {
            match attestation_service_message {
                // TODO: Implement
                AttServiceMessage::Subscribe(_subnet) => { },
                AttServiceMessage::Unsubscribe(_subnet) => { },
                AttServiceMessage::EnrAdd(_subnet) => { },
                AttServiceMessage::EnrRemove(_subnet) => { },
                AttServiceMessage::DiscoverPeers(_subnet) => { },
            }
        }

        let mut peers_to_ban = Vec::new();
        // poll the swarm
        loop {
            match service.libp2p.poll() {
                Ok(Async::Ready(Some(event))) => match event {
                    Libp2pEvent::RPC(peer_id, rpc_event) => {
                        // trace!(log, "Received RPC"; "rpc" => format!("{}", rpc_event));

                        // if we received a Goodbye message, drop and ban the peer
                        if let RPCEvent::Request(_, RPCRequest::Goodbye(_)) = rpc_event {
                            peers_to_ban.push(peer_id.clone());
                        };
                        service.router_send
                            .try_send(RouterMessage::RPC(peer_id, rpc_event))
                            .map_err(|_| { debug!(log, "Failed to send RPC to router");} )?;
                    }
                    Libp2pEvent::PeerDialed(peer_id) => {
                        debug!(log, "Peer Dialed"; "peer_id" => format!("{:?}", peer_id));
                        service.router_send
                            .try_send(RouterMessage::PeerDialed(peer_id))
                            .map_err(|_| { debug!(log, "Failed to send peer dialed to router");})?;
                    }
                    Libp2pEvent::PeerDisconnected(peer_id) => {
                        debug!(log, "Peer Disconnected";  "peer_id" => format!("{:?}", peer_id));
                        service.router_send
                            .try_send(RouterMessage::PeerDisconnected(peer_id))
                            .map_err(|_| { debug!(log, "Failed to send peer disconnect to router");})?;
                    }
                    Libp2pEvent::PubsubMessage {
                        id,
                        source,
                        message,
                        ..
                    } => {
                       service.router_send
                            .try_send(RouterMessage::PubsubMessage(id, source, message))
                            .map_err(|_| { debug!(log, "Failed to send pubsub message to router");})?;
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
            service.libp2p.disconnect_and_ban_peer(
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
pub enum NetworkMessage<T: EthSpec> {
    /// Subscribes a list of validators to specific slots for attestation duties.
    Subscribe {
        subscriptions: Vec<ValidatorSubscription>,
    },
    /// Send an RPC message to the libp2p service.
    RPC(PeerId, RPCEvent<T>),
    /// Publish a list of messages to the gossipsub protocol.
    Publish { messages: Vec<PubsubMessage<T>> },
    /// Propagate a received gossipsub message.
    Propagate {
        propagation_source: PeerId,
        message_id: MessageId,
    },
    /// Disconnect and bans a peer id.
    Disconnect { peer_id: PeerId },
}
