use crate::persisted_dht::{load_dht, persist_dht};
use crate::router::{Router, RouterMessage};
use crate::{
    attestation_service::{AttServiceMessage, AttestationService},
    NetworkConfig,
};
use crate::{error, metrics};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{
    rpc::{GoodbyeReason, RPCResponseErrorCode, RequestId},
    Libp2pEvent, PeerAction, PeerRequestId, PubsubMessage, Request, Response,
};
use eth2_libp2p::{BehaviourEvent, MessageId, NetworkGlobals, PeerId};
use eth2_libp2p::{MessageAcceptance, Service as LibP2PService};
use futures::prelude::*;
use rest_types::ValidatorSubscription;
use slog::{debug, error, info, o, trace, warn};
use std::sync::Arc;
use std::time::Duration;
use store::HotColdDB;
use tokio::sync::mpsc;
use tokio::time::Delay;
use types::EthSpec;

mod tests;

/// Types of messages that the network service can receive.
#[derive(Debug)]
pub enum NetworkMessage<T: EthSpec> {
    /// Subscribes a list of validators to specific slots for attestation duties.
    Subscribe {
        subscriptions: Vec<ValidatorSubscription>,
    },
    /// Send an RPC request to the libp2p service.
    SendRequest {
        peer_id: PeerId,
        request: Request,
        request_id: RequestId,
    },
    /// Send a successful Response to the libp2p service.
    SendResponse {
        peer_id: PeerId,
        response: Response<T>,
        id: PeerRequestId,
    },
    /// Respond to a peer's request with an error.
    SendError {
        // TODO: note that this is never used, we just say goodbye without nicely closing the
        // stream assigned to the request
        peer_id: PeerId,
        error: RPCResponseErrorCode,
        reason: String,
        id: PeerRequestId,
    },
    /// Publish a list of messages to the gossipsub protocol.
    Publish { messages: Vec<PubsubMessage<T>> },
    /// Validates a received gossipsub message. This will propagate the message on the network.
    ValidationResult {
        /// The peer that sent us the message. We don't send back to this peer.
        propagation_source: PeerId,
        /// The id of the message we are validating and propagating.
        message_id: MessageId,
        /// The result of the validation
        validation_result: MessageAcceptance,
    },
    /// Reports a peer to the peer manager for performing an action.
    ReportPeer { peer_id: PeerId, action: PeerAction },
    /// Disconnect an ban a peer, providing a reason.
    GoodbyePeer {
        peer_id: PeerId,
        reason: GoodbyeReason,
    },
}

/// Service that handles communication between internal services and the `eth2_libp2p` network service.
pub struct NetworkService<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    beacon_chain: Arc<BeaconChain<T>>,
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
    store: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    /// A collection of global variables, accessible outside of the network service.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    /// A delay that expires when a new fork takes place.
    next_fork_update: Option<Delay>,
    /// The logger for the network service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> NetworkService<T> {
    #[allow(clippy::type_complexity)]
    pub async fn start(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        executor: environment::TaskExecutor,
    ) -> error::Result<(
        Arc<NetworkGlobals<T::EthSpec>>,
        mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    )> {
        let network_log = executor.log().clone();
        // build the network channel
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage<T::EthSpec>>();
        // get a reference to the beacon chain store
        let store = beacon_chain.store.clone();

        // build the current enr_fork_id for adding to our local ENR
        let enr_fork_id = beacon_chain.enr_fork_id();

        // keep track of when our fork_id needs to be updated
        let next_fork_update = next_fork_delay(&beacon_chain);

        // launch libp2p service
        let (network_globals, mut libp2p) =
            LibP2PService::new(executor.clone(), config, enr_fork_id, &network_log).await?;

        // Repopulate the DHT with stored ENR's.
        let enrs_to_load = load_dht::<T::EthSpec, T::HotStore, T::ColdStore>(store.clone());
        debug!(
            network_log,
            "Loading peers into the routing table"; "peers" => enrs_to_load.len()
        );
        for enr in enrs_to_load {
            libp2p.swarm.add_enr(enr.clone()); //TODO change?
        }

        // launch derived network services

        // router task
        let router_send = Router::spawn(
            beacon_chain.clone(),
            network_globals.clone(),
            network_send.clone(),
            executor.clone(),
            network_log.clone(),
        )?;

        // attestation service
        let attestation_service =
            AttestationService::new(beacon_chain.clone(), network_globals.clone(), &network_log);

        // create the network service and spawn the task
        let network_log = network_log.new(o!("service" => "network"));
        let network_service = NetworkService {
            beacon_chain,
            libp2p,
            attestation_service,
            network_recv,
            router_send,
            store,
            network_globals: network_globals.clone(),
            next_fork_update,
            log: network_log,
        };

        spawn_service(executor, network_service)?;

        Ok((network_globals, network_send))
    }
}

fn spawn_service<T: BeaconChainTypes>(
    executor: environment::TaskExecutor,
    mut service: NetworkService<T>,
) -> error::Result<()> {
    let mut exit_rx = executor.exit();
    let mut shutdown_sender = executor.shutdown_sender();

    // spawn on the current executor
    executor.spawn_without_exit(async move {
        // TODO: there is something with this code that prevents cargo fmt from doing anything at
        // all. Ok, it is worse, the compiler doesn't show errors over this code beyond ast
        // checking
        loop {
            // build the futures to check simultaneously
            tokio::select! {
                // handle network shutdown
                _ = (&mut exit_rx) => {
                    // network thread is terminating
                    let enrs = service.libp2p.swarm.enr_entries();
                    debug!(
                        service.log,
                        "Persisting DHT to store";
                        "Number of peers" => format!("{}", enrs.len()),
                    );

                    match persist_dht::<T::EthSpec, T::HotStore, T::ColdStore>(service.store.clone(), enrs) {
                        Err(e) => error!(
                            service.log,
                            "Failed to persist DHT on drop";
                            "error" => format!("{:?}", e)
                        ),
                        Ok(_) => info!(
                            service.log,
                            "Saved DHT state";
                        ),
                    }

                    info!(service.log, "Network service shutdown");
                    return;
                }
                // handle a message sent to the network
                Some(message) = service.network_recv.recv() => {
                    match message {
                        NetworkMessage::SendRequest{ peer_id, request, request_id } => {
                            service.libp2p.send_request(peer_id, request_id, request);
                        }
                        NetworkMessage::SendResponse{ peer_id, response, id } => {
                            service.libp2p.send_response(peer_id, id, response);
                        }
                        NetworkMessage::SendError{ peer_id, error, id, reason } => {
                            service.libp2p.respond_with_error(peer_id, id, error, reason);
                        }
                        NetworkMessage::ValidationResult {
                            propagation_source,
                            message_id,
                            validation_result,
                        } => {
                                trace!(service.log, "Propagating gossipsub message";
                                    "propagation_peer" => format!("{:?}", propagation_source),
                                    "message_id" => message_id.to_string(),
                                );
                                service
                                    .libp2p
                                    .swarm
                                    .report_message_validation_result(
                                        &propagation_source, message_id, validation_result
                                    );
                        }
                        NetworkMessage::Publish { messages } => {
                                let mut topic_kinds = Vec::new();
                                for message in &messages {
                                    if !topic_kinds.contains(&message.kind()) {
                                        topic_kinds.push(message.kind());
                                    }
                                }
                                debug!(
                                    service.log,
                                    "Sending pubsub messages";
                                    "count" => messages.len(),
                                    "topics" => format!("{:?}", topic_kinds)
                                );
                                expose_publish_metrics(&messages);
                                service.libp2p.swarm.publish(messages);
                        }
                        NetworkMessage::ReportPeer { peer_id, action } => service.libp2p.report_peer(&peer_id, action),
                        NetworkMessage::GoodbyePeer { peer_id, reason } => service.libp2p.goodbye_peer(&peer_id, reason),
                        NetworkMessage::Subscribe { subscriptions } => {
                            if let Err(e) = service
                                .attestation_service
                                .validator_subscriptions(subscriptions) {
                                    warn!(service.log, "Validator subscription failed"; "error" => e);
                                }
                        }
                    }
                }
                // process any attestation service events
                Some(attestation_service_message) = service.attestation_service.next() => {
                    match attestation_service_message {
                        // TODO: Implement
                        AttServiceMessage::Subscribe(subnet_id) => {
                            service.libp2p.swarm.subscribe_to_subnet(subnet_id);
                        }
                        AttServiceMessage::Unsubscribe(subnet_id) => {
                            service.libp2p.swarm.subscribe_to_subnet(subnet_id);
                        }
                        AttServiceMessage::EnrAdd(subnet_id) => {
                            service.libp2p.swarm.update_enr_subnet(subnet_id, true);
                        }
                        AttServiceMessage::EnrRemove(subnet_id) => {
                            service.libp2p.swarm.update_enr_subnet(subnet_id, false);
                        }
                        AttServiceMessage::DiscoverPeers(subnets_to_discover) => {
                            service.libp2p.swarm.discover_subnet_peers(subnets_to_discover);
                        }
                    }
                }
                libp2p_event = service.libp2p.next_event() => {
                    // poll the swarm
                    match libp2p_event {
                        Libp2pEvent::Behaviour(event) => match event {

                            BehaviourEvent::PeerDialed(peer_id) => {
                                    let _ = service
                                        .router_send
                                        .send(RouterMessage::PeerDialed(peer_id))
                                        .map_err(|_| {
                                            debug!(service.log, "Failed to send peer dialed to router"); });
                            },
                            BehaviourEvent::PeerConnected(_peer_id) => {
                                // A peer has connected to us
                                // We currently do not perform any action here.
                            },
                            BehaviourEvent::PeerDisconnected(peer_id) => {
                            let _ = service
                                .router_send
                                .send(RouterMessage::PeerDisconnected(peer_id))
                                .map_err(|_| {
                                    debug!(service.log, "Failed to send peer disconnect to router");
                                });
                            },
                            BehaviourEvent::RequestReceived{peer_id, id, request} => {
                                let _ = service
                                    .router_send
                                    .send(RouterMessage::RPCRequestReceived{peer_id, id, request})
                                    .map_err(|_| {
                                        debug!(service.log, "Failed to send RPC to router");
                                    });
                            }
                            BehaviourEvent::ResponseReceived{peer_id, id, response} => {
                                let _ = service
                                    .router_send
                                    .send(RouterMessage::RPCResponseReceived{ peer_id, request_id: id, response })
                                    .map_err(|_| {
                                        debug!(service.log, "Failed to send RPC to router");
                                    });

                            }
                            BehaviourEvent::RPCFailed{id, peer_id, error} => {
                                let _ = service
                                    .router_send
                                    .send(RouterMessage::RPCFailed{ peer_id, request_id: id, error })
                                    .map_err(|_| {
                                        debug!(service.log, "Failed to send RPC to router");
                                    });

                            }
                            BehaviourEvent::StatusPeer(peer_id) => {
                                let _ = service
                                    .router_send
                                    .send(RouterMessage::StatusPeer(peer_id))
                                    .map_err(|_| {
                                        debug!(service.log, "Failed to send re-status  peer to router");
                                    });
                            }
                            BehaviourEvent::PubsubMessage {
                                id,
                                source,
                                message,
                                ..
                            } => {
                                // Update prometheus metrics.
                                expose_receive_metrics(&message);
                                match message {
                                    // attestation information gets processed in the attestation service
                                    PubsubMessage::Attestation(ref subnet_and_attestation) => {
                                        let subnet = subnet_and_attestation.0;
                                        let attestation = &subnet_and_attestation.1;
                                        // checks if we have an aggregator for the slot. If so, we should process
                                        // the attestation, else we just just propagate the Attestation.
                                        let should_process = service.attestation_service.should_process_attestation(
                                            subnet,
                                            attestation,
                                        );
                                        let _ = service
                                            .router_send
                                            .send(RouterMessage::PubsubMessage(id, source, message, should_process))
                                            .map_err(|_| {
                                                debug!(service.log, "Failed to send pubsub message to router");
                                            });
                                    }
                                    _ => {
                                        // all else is sent to the router
                                        let _ = service
                                            .router_send
                                            .send(RouterMessage::PubsubMessage(id, source, message, true))
                                            .map_err(|_| {
                                                debug!(service.log, "Failed to send pubsub message to router");
                                            });
                                    }
                                }
                            }
                            BehaviourEvent::PeerSubscribed(_, _) => {},
                        }
                        Libp2pEvent::NewListenAddr(multiaddr) => {
                            service.network_globals.listen_multiaddrs.write().push(multiaddr);
                        }
                        Libp2pEvent::ZeroListeners => {
                            let _ = shutdown_sender.send("All listeners are closed. Unable to listen").await.map_err(|e| {
                                warn!(service.log, "failed to send a shutdown signal"; "error" => e.to_string()
                                )
                            });
                        }
                    }
                }
            }

            if let Some(delay) = &service.next_fork_update {
                if delay.is_elapsed() {
                    service
                        .libp2p
                        .swarm
                        .update_fork_version(service.beacon_chain.enr_fork_id());
                    service.next_fork_update = next_fork_delay(&service.beacon_chain);
                }
            }
        }
    }, "network");

    Ok(())
}

/// Returns a `Delay` that triggers shortly after the next change in the beacon chain fork version.
/// If there is no scheduled fork, `None` is returned.
fn next_fork_delay<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> Option<tokio::time::Delay> {
    beacon_chain.duration_to_next_fork().map(|until_fork| {
        // Add a short time-out to start within the new fork period.
        let delay = Duration::from_millis(200);
        tokio::time::delay_until(tokio::time::Instant::now() + until_fork + delay)
    })
}

/// Inspects the `messages` that were being sent to the network and updates Prometheus metrics.
fn expose_publish_metrics<T: EthSpec>(messages: &[PubsubMessage<T>]) {
    for message in messages {
        match message {
            PubsubMessage::BeaconBlock(_) => metrics::inc_counter(&metrics::GOSSIP_BLOCKS_TX),
            PubsubMessage::Attestation(_) => {
                metrics::inc_counter(&metrics::GOSSIP_UNAGGREGATED_ATTESTATIONS_TX)
            }
            PubsubMessage::AggregateAndProofAttestation(_) => {
                metrics::inc_counter(&metrics::GOSSIP_AGGREGATED_ATTESTATIONS_TX)
            }
            _ => {}
        }
    }
}

/// Inspects a `message` received from the network and updates Prometheus metrics.
fn expose_receive_metrics<T: EthSpec>(message: &PubsubMessage<T>) {
    match message {
        PubsubMessage::BeaconBlock(_) => metrics::inc_counter(&metrics::GOSSIP_BLOCKS_RX),
        PubsubMessage::Attestation(_) => {
            metrics::inc_counter(&metrics::GOSSIP_UNAGGREGATED_ATTESTATIONS_RX)
        }
        PubsubMessage::AggregateAndProofAttestation(_) => {
            metrics::inc_counter(&metrics::GOSSIP_AGGREGATED_ATTESTATIONS_RX)
        }
        _ => {}
    }
}
