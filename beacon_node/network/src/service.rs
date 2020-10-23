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
    Gossipsub, Libp2pEvent, PeerAction, PeerRequestId, PubsubMessage, Request, Response,
};
use eth2_libp2p::{
    types::GossipKind, BehaviourEvent, GossipTopic, MessageId, NetworkGlobals, PeerId, TopicHash,
};
use eth2_libp2p::{MessageAcceptance, Service as LibP2PService};
use futures::prelude::*;
use slog::{debug, error, info, o, trace, warn};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use store::HotColdDB;
use tokio::sync::mpsc;
use tokio::time::Delay;
use types::{EthSpec, ValidatorSubscription};

mod tests;

/// The interval (in seconds) that various network metrics will update.
const METRIC_UPDATE_INTERVAL: u64 = 1;

/// Types of messages that the network service can receive.
#[derive(Debug)]
pub enum NetworkMessage<T: EthSpec> {
    /// Subscribes a list of validators to specific slots for attestation duties.
    Subscribe {
        subscriptions: Vec<ValidatorSubscription>,
    },
    /// Subscribes the beacon node to the core gossipsub topics. We do this when we are either
    /// synced or close to the head slot.
    SubscribeCoreTopics,
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
        // NOTE: Currently this is never used, we just say goodbye without nicely closing the
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
    /// Called if a known external TCP socket address has been updated.
    UPnPMappingEstablished {
        /// The external TCP address has been updated.
        tcp_socket: Option<SocketAddr>,
        /// The external UDP address has been updated.
        udp_socket: Option<SocketAddr>,
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
    /// Stores potentially created UPnP mappings to be removed on shutdown. (TCP port and UDP
    /// port).
    upnp_mappings: (Option<u16>, Option<u16>),
    /// Keeps track of if discovery is auto-updating or not. This is used to inform us if we should
    /// update the UDP socket of discovery if the UPnP mappings get established.
    discovery_auto_update: bool,
    /// A delay that expires when a new fork takes place.
    next_fork_update: Option<Delay>,
    /// A timer for updating various network metrics.
    metrics_update: tokio::time::Interval,
    /// The logger for the network service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> NetworkService<T> {
    #[allow(clippy::type_complexity)]
    pub async fn start(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        executor: task_executor::TaskExecutor,
    ) -> error::Result<(
        Arc<NetworkGlobals<T::EthSpec>>,
        mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    )> {
        let network_log = executor.log().clone();
        // build the network channel
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage<T::EthSpec>>();

        // try and construct UPnP port mappings if required.
        let upnp_config = crate::nat::UPnPConfig::from(config);
        let upnp_log = network_log.new(o!("service" => "UPnP"));
        let upnp_network_send = network_send.clone();
        if config.upnp_enabled {
            executor.spawn_blocking(
                move || {
                    crate::nat::construct_upnp_mappings(upnp_config, upnp_network_send, upnp_log)
                },
                "UPnP",
            );
        }

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
            libp2p.swarm.add_enr(enr.clone());
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
        let attestation_service = AttestationService::new(beacon_chain.clone(), &network_log);

        // create a timer for updating network metrics
        let metrics_update = tokio::time::interval(Duration::from_secs(METRIC_UPDATE_INTERVAL));

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
            upnp_mappings: (None, None),
            discovery_auto_update: config.discv5_config.enr_update,
            next_fork_update,
            metrics_update,
            log: network_log,
        };

        spawn_service(executor, network_service)?;

        Ok((network_globals, network_send))
    }
}

fn spawn_service<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    mut service: NetworkService<T>,
) -> error::Result<()> {
    let mut exit_rx = executor.exit();
    let mut shutdown_sender = executor.shutdown_sender();

    // spawn on the current executor
    executor.spawn_without_exit(async move {

        let mut metric_update_counter = 0;
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

                    // attempt to remove port mappings
                    crate::nat::remove_mappings(service.upnp_mappings.0, service.upnp_mappings.1, &service.log);

                    info!(service.log, "Network service shutdown");
                    return;
                }
                _ = service.metrics_update.next() => {
                    // update various network metrics
                    metric_update_counter +=1;
                    if metric_update_counter* 1000 % T::EthSpec::default_spec().milliseconds_per_slot == 0 {
                        // if a slot has occurred, reset the metrics
                        let _ = metrics::ATTESTATIONS_PUBLISHED_PER_SUBNET_PER_SLOT
                            .as_ref()
                            .map(|gauge| gauge.reset());
                    }
                    update_gossip_metrics::<T::EthSpec>(&service.libp2p.swarm.gs());
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
                        NetworkMessage::UPnPMappingEstablished { tcp_socket, udp_socket} => {
                            service.upnp_mappings = (tcp_socket.map(|s| s.port()), udp_socket.map(|s| s.port()));
                            // If there is an external TCP port update, modify our local ENR.
                            if let Some(tcp_socket) = tcp_socket {
                                if let Err(e) = service.libp2p.swarm.peer_manager().discovery_mut().update_enr_tcp_port(tcp_socket.port()) {
                                    warn!(service.log, "Failed to update ENR"; "error" => e);
                                }
                            }
                            // if the discovery service is not auto-updating, update it with the
                            // UPnP mappings
                            if !service.discovery_auto_update {
                                if let Some(udp_socket) = udp_socket {
                                    if let Err(e) = service.libp2p.swarm.peer_manager().discovery_mut().update_enr_udp_socket(udp_socket) {
                                    warn!(service.log, "Failed to update ENR"; "error" => e);
                                }
                                }
                            }
                        },
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
                        NetworkMessage::SubscribeCoreTopics => {
                            let mut subscribed_topics: Vec<GossipKind> = vec![];
                            let already_subscribed = service.network_globals.gossipsub_subscriptions.read().clone();
                            let already_subscribed = already_subscribed.iter().map(|x| x.kind()).collect::<std::collections::HashSet<_>>();
                            for topic_kind in eth2_libp2p::types::CORE_TOPICS.iter().filter(|topic| already_subscribed.get(topic).is_none()) {
                                if service.libp2p.swarm.subscribe_kind(topic_kind.clone()) {
                                    subscribed_topics.push(topic_kind.clone());
                                } else {
                                    warn!(service.log, "Could not subscribe to topic"; "topic" => format!("{}",topic_kind));
                                }
                            }
                            if !subscribed_topics.is_empty() {
                                info!(service.log, "Subscribed to topics"; "topics" => format!("{:?}", subscribed_topics));
                            }
                        }
                    }
                }
                // process any attestation service events
                Some(attestation_service_message) = service.attestation_service.next() => {
                    match attestation_service_message {
                        AttServiceMessage::Subscribe(subnet_id) => {
                            service.libp2p.swarm.subscribe_to_subnet(subnet_id);
                        }
                        AttServiceMessage::Unsubscribe(subnet_id) => {
                            service.libp2p.swarm.unsubscribe_from_subnet(subnet_id);
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
            PubsubMessage::Attestation(subnet_id) => {
                metrics::inc_counter_vec(
                    &metrics::ATTESTATIONS_PUBLISHED_PER_SUBNET_PER_SLOT,
                    &[&subnet_id.0.to_string()],
                );
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

fn update_gossip_metrics<T: EthSpec>(gossipsub: &Gossipsub) {
    // Clear the metrics
    let _ = metrics::PEERS_PER_PROTOCOL
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = metrics::PEERS_PER_PROTOCOL
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = metrics::MESH_PEERS_PER_MAIN_TOPIC
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = metrics::AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC
        .as_ref()
        .map(|gauge| gauge.reset());
    let _ = metrics::AVG_GOSSIPSUB_PEER_SCORE_PER_SUBNET_TOPIC
        .as_ref()
        .map(|gauge| gauge.reset());

    // reset the mesh peers, showing all subnets
    for subnet_id in 0..T::default_spec().attestation_subnet_count {
        let _ = metrics::get_int_gauge(
            &metrics::MESH_PEERS_PER_SUBNET_TOPIC,
            &[&subnet_id.to_string()],
        )
        .map(|v| v.set(0));

        let _ = metrics::get_int_gauge(
            &metrics::GOSSIPSUB_SUBSCRIBED_SUBNET_TOPIC,
            &[&subnet_id.to_string()],
        )
        .map(|v| v.set(0));

        let _ = metrics::get_int_gauge(
            &metrics::GOSSIPSUB_SUBSCRIBED_PEERS_SUBNET_TOPIC,
            &[&subnet_id.to_string()],
        )
        .map(|v| v.set(0));
    }

    // Subnet topics subscribed to
    for topic_hash in gossipsub.topics() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            if let GossipKind::Attestation(subnet_id) = topic.kind() {
                let _ = metrics::get_int_gauge(
                    &metrics::GOSSIPSUB_SUBSCRIBED_SUBNET_TOPIC,
                    &[&subnet_id.to_string()],
                )
                .map(|v| v.set(1));
            }
        }
    }

    // Peers per subscribed subnet
    let mut peers_per_topic: HashMap<TopicHash, usize> = HashMap::new();
    for (peer_id, topics) in gossipsub.all_peers() {
        for topic_hash in topics {
            *peers_per_topic.entry(topic_hash.clone()).or_default() += 1;

            if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
                match topic.kind() {
                    GossipKind::Attestation(subnet_id) => {
                        if let Some(v) = metrics::get_int_gauge(
                            &metrics::GOSSIPSUB_SUBSCRIBED_PEERS_SUBNET_TOPIC,
                            &[&subnet_id.to_string()],
                        ) {
                            v.inc()
                        };

                        // average peer scores
                        if let Some(score) = gossipsub.peer_score(peer_id) {
                            if let Some(v) = metrics::get_int_gauge(
                                &metrics::AVG_GOSSIPSUB_PEER_SCORE_PER_SUBNET_TOPIC,
                                &[&subnet_id.to_string()],
                            ) {
                                v.add(score as i64)
                            };
                        }
                    }
                    kind => {
                        // main topics
                        if let Some(score) = gossipsub.peer_score(peer_id) {
                            if let Some(v) = metrics::get_int_gauge(
                                &metrics::AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC,
                                &[&format!("{:?}", kind)],
                            ) {
                                v.add(score as i64)
                            };
                        }
                    }
                }
            }
        }
    }
    // adjust to average scores by dividing by number of peers
    for (topic_hash, peers) in peers_per_topic.iter() {
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::Attestation(subnet_id) => {
                    // average peer scores
                    if let Some(v) = metrics::get_int_gauge(
                        &metrics::AVG_GOSSIPSUB_PEER_SCORE_PER_SUBNET_TOPIC,
                        &[&subnet_id.to_string()],
                    ) {
                        v.set(v.get() / (*peers as i64))
                    };
                }
                kind => {
                    // main topics
                    if let Some(v) = metrics::get_int_gauge(
                        &metrics::AVG_GOSSIPSUB_PEER_SCORE_PER_MAIN_TOPIC,
                        &[&format!("{:?}", kind)],
                    ) {
                        v.set(v.get() / (*peers as i64))
                    };
                }
            }
        }
    }

    // mesh peers
    for topic_hash in gossipsub.topics() {
        let peers = gossipsub.mesh_peers(&topic_hash).count();
        if let Ok(topic) = GossipTopic::decode(topic_hash.as_str()) {
            match topic.kind() {
                GossipKind::Attestation(subnet_id) => {
                    if let Some(v) = metrics::get_int_gauge(
                        &metrics::MESH_PEERS_PER_SUBNET_TOPIC,
                        &[&subnet_id.to_string()],
                    ) {
                        v.set(peers as i64)
                    };
                }
                kind => {
                    // main topics
                    if let Some(v) = metrics::get_int_gauge(
                        &metrics::MESH_PEERS_PER_MAIN_TOPIC,
                        &[&format!("{:?}", kind)],
                    ) {
                        v.set(peers as i64)
                    };
                }
            }
        }
    }

    // protocol peers
    let mut peers_per_protocol: HashMap<String, i64> = HashMap::new();
    for (_peer, protocol) in gossipsub.peer_protocol() {
        *peers_per_protocol.entry(protocol.to_string()).or_default() += 1;
    }

    for (protocol, peers) in peers_per_protocol.iter() {
        if let Some(v) =
            metrics::get_int_gauge(&metrics::PEERS_PER_PROTOCOL, &[&protocol.to_string()])
        {
            v.set(*peers)
        };
    }
}
