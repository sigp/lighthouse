use crate::persisted_dht::{clear_dht, load_dht, persist_dht};
use crate::router::{Router, RouterMessage};
use crate::subnet_service::SyncCommitteeService;
use crate::{error, metrics};
use crate::{
    subnet_service::{AttestationService, SubnetServiceMessage},
    NetworkConfig,
};
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2_libp2p::{
    rpc::{GoodbyeReason, RPCResponseErrorCode, RequestId},
    Libp2pEvent, PeerAction, PeerRequestId, PubsubMessage, ReportSource, Request, Response, Subnet,
};
use eth2_libp2p::{
    types::{GossipEncoding, GossipTopic},
    BehaviourEvent, MessageId, NetworkGlobals, PeerId,
};
use eth2_libp2p::{MessageAcceptance, Service as LibP2PService};
use futures::future::OptionFuture;
use futures::prelude::*;
use slog::{crit, debug, error, info, o, trace, warn};
use std::{net::SocketAddr, pin::Pin, sync::Arc, time::Duration};
use store::HotColdDB;
use task_executor::ShutdownReason;
use tokio::sync::mpsc;
use tokio::time::Sleep;
use types::{
    ChainSpec, EthSpec, ForkContext, ForkName, RelativeEpoch, Slot, SubnetId,
    SyncCommitteeSubscription, SyncSubnetId, Unsigned, ValidatorSubscription,
};

mod tests;

/// The interval (in seconds) that various network metrics will update.
const METRIC_UPDATE_INTERVAL: u64 = 1;
/// Number of slots before the fork when we should subscribe to the new fork topics.
const SUBSCRIBE_DELAY_SLOTS: u64 = 2;
/// Delay after a fork where we unsubscribe from pre-fork topics.
const UNSUBSCRIBE_DELAY_EPOCHS: u64 = 2;

/// Types of messages that the network service can receive.
#[derive(Debug)]
pub enum NetworkMessage<T: EthSpec> {
    /// Subscribes a list of validators to specific slots for attestation duties.
    AttestationSubscribe {
        subscriptions: Vec<ValidatorSubscription>,
    },
    SyncCommitteeSubscribe {
        subscriptions: Vec<SyncCommitteeSubscription>,
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
    /// Sends an error response to an RPC request.
    SendErrorResponse {
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
    ReportPeer {
        peer_id: PeerId,
        action: PeerAction,
        source: ReportSource,
    },
    /// Disconnect an ban a peer, providing a reason.
    GoodbyePeer {
        peer_id: PeerId,
        reason: GoodbyeReason,
        source: ReportSource,
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
    /// A sync committeee subnet manager service.
    sync_committee_service: SyncCommitteeService<T>,
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
    next_fork_update: Pin<Box<OptionFuture<Sleep>>>,
    /// A delay that expires when we need to subscribe to a new fork's topics.
    next_fork_subscriptions: Pin<Box<OptionFuture<Sleep>>>,
    /// A delay that expires when we need to unsubscribe from old fork topics.
    next_unsubscribe: Pin<Box<OptionFuture<Sleep>>>,
    /// Subscribe to all the subnets once synced.
    subscribe_all_subnets: bool,
    /// Shutdown beacon node after sync is complete.
    shutdown_after_sync: bool,
    /// A timer for updating various network metrics.
    metrics_update: tokio::time::Interval,
    /// gossipsub_parameter_update timer
    gossipsub_parameter_update: tokio::time::Interval,
    /// The logger for the network service.
    fork_context: Arc<ForkContext>,
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
        let next_fork_update = Box::pin(next_fork_delay(&beacon_chain).into());
        let next_fork_subscriptions = Box::pin(next_fork_subscriptions_delay(&beacon_chain).into());
        let next_unsubscribe = Box::pin(None.into());

        let current_slot = beacon_chain
            .slot()
            .unwrap_or(beacon_chain.spec.genesis_slot);

        // Create a fork context for the given config and genesis validators root
        let fork_context = Arc::new(ForkContext::new::<T::EthSpec>(
            current_slot,
            beacon_chain.genesis_validators_root,
            &beacon_chain.spec,
        ));

        debug!(network_log, "Current fork"; "fork_name" => ?fork_context.current_fork());

        // launch libp2p service
        let (network_globals, mut libp2p) = LibP2PService::new(
            executor.clone(),
            config,
            enr_fork_id,
            &network_log,
            fork_context.clone(),
            &beacon_chain.spec,
        )
        .await?;

        // Repopulate the DHT with stored ENR's if discovery is not disabled.
        if !config.disable_discovery {
            let enrs_to_load = load_dht::<T::EthSpec, T::HotStore, T::ColdStore>(store.clone());
            debug!(
                network_log,
                "Loading peers into the routing table"; "peers" => enrs_to_load.len()
            );
            for enr in enrs_to_load {
                libp2p.swarm.behaviour_mut().add_enr(enr.clone());
            }
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

        // attestation subnet service
        let attestation_service =
            AttestationService::new(beacon_chain.clone(), config, &network_log);

        // sync committee subnet service
        let sync_committee_service =
            SyncCommitteeService::new(beacon_chain.clone(), config, &network_log);

        // create a timer for updating network metrics
        let metrics_update = tokio::time::interval(Duration::from_secs(METRIC_UPDATE_INTERVAL));

        // create a timer for updating gossipsub parameters
        let gossipsub_parameter_update = tokio::time::interval(Duration::from_secs(60));

        // create the network service and spawn the task
        let network_log = network_log.new(o!("service" => "network"));
        let network_service = NetworkService {
            beacon_chain,
            libp2p,
            attestation_service,
            sync_committee_service,
            network_recv,
            router_send,
            store,
            network_globals: network_globals.clone(),
            upnp_mappings: (None, None),
            discovery_auto_update: config.discv5_config.enr_update,
            next_fork_update,
            next_fork_subscriptions,
            next_unsubscribe,
            subscribe_all_subnets: config.subscribe_all_subnets,
            shutdown_after_sync: config.shutdown_after_sync,
            metrics_update,
            gossipsub_parameter_update,
            fork_context,
            log: network_log,
        };

        spawn_service(executor, network_service);

        Ok((network_globals, network_send))
    }

    /// Returns the required fork digests that gossipsub needs to subscribe to based on the current slot.
    ///
    /// For `current_slot < fork_slot`, this function returns both the pre-fork and post-fork
    /// digests since we should be subscribed to post fork topics before the fork.
    pub fn required_gossip_fork_digests(&self) -> Vec<[u8; 4]> {
        let fork_context = &self.fork_context;
        let spec = &self.beacon_chain.spec;
        match fork_context.current_fork() {
            ForkName::Base => {
                // If we are SUBSCRIBE_DELAY_SLOTS before the fork slot, subscribe only to Base,
                // else subscribe to Base and Altair.
                let current_slot = self.beacon_chain.slot().unwrap_or(spec.genesis_slot);
                match spec.next_fork_epoch::<T::EthSpec>(current_slot) {
                    Some((_, fork_epoch)) => {
                        if current_slot.saturating_add(Slot::new(SUBSCRIBE_DELAY_SLOTS))
                            >= fork_epoch.start_slot(T::EthSpec::slots_per_epoch())
                        {
                            fork_context.all_fork_digests()
                        } else {
                            vec![fork_context.genesis_context_bytes()]
                        }
                    }
                    None => vec![fork_context.genesis_context_bytes()],
                }
            }
            ForkName::Altair => vec![fork_context
                .to_context_bytes(ForkName::Altair)
                .expect("Altair fork bytes should exist as it's initialized in ForkContext")],
        }
    }
}

fn spawn_service<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    mut service: NetworkService<T>,
) {
    let mut shutdown_sender = executor.shutdown_sender();

    // spawn on the current executor
    executor.spawn(async move {

        let mut metric_update_counter = 0;
        loop {
            // build the futures to check simultaneously
            tokio::select! {
                _ = service.metrics_update.tick() => {
                    // update various network metrics
                    metric_update_counter +=1;
                    if metric_update_counter % T::EthSpec::default_spec().seconds_per_slot == 0 {
                        // if a slot has occurred, reset the metrics
                        let _ = metrics::ATTESTATIONS_PUBLISHED_PER_SUBNET_PER_SLOT
                            .as_ref()
                            .map(|gauge| gauge.reset());
                    }
                    metrics::update_gossip_metrics::<T::EthSpec>(
                        service.libp2p.swarm.behaviour_mut().gs(),
                        &service.network_globals,
                    );
                    // update sync metrics
                    metrics::update_sync_metrics(&service.network_globals);

                }
                _ = service.gossipsub_parameter_update.tick() => {
                    if let Ok(slot) = service.beacon_chain.slot() {
                        if let Some(active_validators) = service.beacon_chain.with_head(|head| {
                                Ok::<_, BeaconChainError>(
                                    head
                                    .beacon_state
                                    .get_cached_active_validator_indices(RelativeEpoch::Current)
                                    .map(|indices| indices.len())
                                    .ok()
                                    .or_else(|| {
                                        // if active validator cached was not build we count the
                                        // active validators
                                        service
                                            .beacon_chain
                                            .epoch()
                                            .ok()
                                            .map(|current_epoch| {
                                                head
                                                .beacon_state
                                                .validators()
                                                .iter()
                                                .filter(|validator|
                                                    validator.is_active_at(current_epoch)
                                                )
                                                .count()
                                            })
                                    })
                                )
                            }).unwrap_or(None) {
                            if service.libp2p.swarm.behaviour_mut().update_gossipsub_parameters(active_validators, slot).is_err() {
                                error!(
                                    service.log,
                                    "Failed to update gossipsub parameters";
                                    "active_validators" => active_validators
                                );
                            }
                        }
                    }
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
                        NetworkMessage::SendErrorResponse{ peer_id, error, id, reason } => {
                            service.libp2p.respond_with_error(peer_id, id, error, reason);
                        }
                        NetworkMessage::UPnPMappingEstablished { tcp_socket, udp_socket} => {
                            service.upnp_mappings = (tcp_socket.map(|s| s.port()), udp_socket.map(|s| s.port()));
                            // If there is an external TCP port update, modify our local ENR.
                            if let Some(tcp_socket) = tcp_socket {
                                if let Err(e) = service.libp2p.swarm.behaviour_mut().discovery_mut().update_enr_tcp_port(tcp_socket.port()) {
                                    warn!(service.log, "Failed to update ENR"; "error" => e);
                                }
                            }
                            // if the discovery service is not auto-updating, update it with the
                            // UPnP mappings
                            if !service.discovery_auto_update {
                                if let Some(udp_socket) = udp_socket {
                                    if let Err(e) = service.libp2p.swarm.behaviour_mut().discovery_mut().update_enr_udp_socket(udp_socket) {
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
                                    "propagation_peer" => ?propagation_source,
                                    "message_id" => %message_id,
                                    "validation_result" => ?validation_result
                                );
                                service
                                    .libp2p
                                    .swarm
                                    .behaviour_mut()
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
                                    "topics" => ?topic_kinds
                                );
                                metrics::expose_publish_metrics(&messages);
                                service.libp2p.swarm.behaviour_mut().publish(messages);
                        }
                        NetworkMessage::ReportPeer { peer_id, action, source } => service.libp2p.report_peer(&peer_id, action, source),
                        NetworkMessage::GoodbyePeer { peer_id, reason, source } => service.libp2p.goodbye_peer(&peer_id, reason, source),
                        NetworkMessage::AttestationSubscribe { subscriptions } => {
                            if let Err(e) = service
                                .attestation_service
                                .validator_subscriptions(subscriptions) {
                                    warn!(service.log, "Attestation validator subscription failed"; "error" => e);
                                }
                        }
                        NetworkMessage::SyncCommitteeSubscribe { subscriptions } => {
                            if let Err(e) = service
                                .sync_committee_service
                                .validator_subscriptions(subscriptions) {
                                    warn!(service.log, "Sync committee calidator subscription failed"; "error" => e);
                                }
                        }
                        NetworkMessage::SubscribeCoreTopics => {
                            if service.shutdown_after_sync {
                                let _ = shutdown_sender
                                .send(ShutdownReason::Success(
                                    "Beacon node completed sync. Shutting down as --shutdown-after-sync flag is enabled"))
                                .await
                                .map_err(|e| warn!(
                                    service.log,
                                    "failed to send a shutdown signal";
                                    "error" => %e
                                ));
                                return;
                            }
                            let mut subscribed_topics: Vec<GossipTopic> = vec![];
                            for topic_kind in eth2_libp2p::types::CORE_TOPICS.iter() {
                                for fork_digest in service.required_gossip_fork_digests() {
                                    let topic = GossipTopic::new(topic_kind.clone(), GossipEncoding::default(), fork_digest);
                                    if service.libp2p.swarm.behaviour_mut().subscribe(topic.clone()) {
                                        subscribed_topics.push(topic);
                                    } else {
                                        warn!(service.log, "Could not subscribe to topic"; "topic" => %topic);
                                    }
                                }
                            }

                            // If we are to subscribe to all subnets we do it here
                            if service.subscribe_all_subnets {
                                for subnet_id in 0..<<T as BeaconChainTypes>::EthSpec as EthSpec>::SubnetBitfieldLength::to_u64() {
                                    let subnet = Subnet::Attestation(SubnetId::new(subnet_id));
                                    // Update the ENR bitfield
                                    service.libp2p.swarm.behaviour_mut().update_enr_subnet(subnet, true);
                                    for fork_digest in service.required_gossip_fork_digests() {
                                        let topic = GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                                        if service.libp2p.swarm.behaviour_mut().subscribe(topic.clone()) {
                                            subscribed_topics.push(topic);
                                        } else {
                                            warn!(service.log, "Could not subscribe to topic"; "topic" => %topic);
                                        }
                                    }
                                }
                                for subnet_id in 0..<<T as BeaconChainTypes>::EthSpec as EthSpec>::SyncCommitteeSubnetCount::to_u64() {
                                    let subnet = Subnet::SyncCommittee(SyncSubnetId::new(subnet_id));
                                    // Update the ENR bitfield
                                    service.libp2p.swarm.behaviour_mut().update_enr_subnet(subnet, true);
                                    for fork_digest in service.required_gossip_fork_digests() {
                                        let topic = GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                                        if service.libp2p.swarm.behaviour_mut().subscribe(topic.clone()) {
                                            subscribed_topics.push(topic);
                                        } else {
                                            warn!(service.log, "Could not subscribe to topic"; "topic" => %topic);
                                        }
                                    }
                                }
                            }

                            if !subscribed_topics.is_empty() {
                                info!(
                                    service.log,
                                    "Subscribed to topics";
                                    "topics" => ?subscribed_topics.into_iter().map(|topic| format!("{}", topic)).collect::<Vec<_>>()
                                );
                            }
                        }
                    }
                }
                // process any attestation service events
                Some(attestation_service_message) = service.attestation_service.next() => {
                    match attestation_service_message {
                        SubnetServiceMessage::Subscribe(subnet) => {
                            for fork_digest in service.required_gossip_fork_digests() {
                                let topic = GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                                service.libp2p.swarm.behaviour_mut().subscribe(topic);
                            }
                        }
                        SubnetServiceMessage::Unsubscribe(subnet) => {
                            for fork_digest in service.required_gossip_fork_digests() {
                                let topic = GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                                service.libp2p.swarm.behaviour_mut().unsubscribe(topic);
                            }
                        }
                        SubnetServiceMessage::EnrAdd(subnet) => {
                            service.libp2p.swarm.behaviour_mut().update_enr_subnet(subnet, true);
                        }
                        SubnetServiceMessage::EnrRemove(subnet) => {
                            service.libp2p.swarm.behaviour_mut().update_enr_subnet(subnet, false);
                        }
                        SubnetServiceMessage::DiscoverPeers(subnets_to_discover) => {
                            service.libp2p.swarm.behaviour_mut().discover_subnet_peers(subnets_to_discover);
                        }
                    }
                }
                // process any sync committee service events
                Some(sync_committee_service_message) = service.sync_committee_service.next() => {
                    match sync_committee_service_message {
                        SubnetServiceMessage::Subscribe(subnet) => {
                            for fork_digest in service.required_gossip_fork_digests() {
                                let topic = GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                                service.libp2p.swarm.behaviour_mut().subscribe(topic);
                            }
                        }
                        SubnetServiceMessage::Unsubscribe(subnet) => {
                            for fork_digest in service.required_gossip_fork_digests() {
                                let topic = GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                                service.libp2p.swarm.behaviour_mut().unsubscribe(topic);
                            }
                        }
                        SubnetServiceMessage::EnrAdd(subnet) => {
                            service.libp2p.swarm.behaviour_mut().update_enr_subnet(subnet, true);
                        }
                        SubnetServiceMessage::EnrRemove(subnet) => {
                            service.libp2p.swarm.behaviour_mut().update_enr_subnet(subnet, false);
                        }
                        SubnetServiceMessage::DiscoverPeers(subnets_to_discover) => {
                            service.libp2p.swarm.behaviour_mut().discover_subnet_peers(subnets_to_discover);
                        }
                    }
                }
                libp2p_event = service.libp2p.next_event() => {
                    // poll the swarm
                    match libp2p_event {
                        Libp2pEvent::Behaviour(event) => match event {
                            BehaviourEvent::PeerConnectedOutgoing(peer_id) => {
                                    let _ = service
                                        .router_send
                                        .send(RouterMessage::PeerDialed(peer_id))
                                        .map_err(|_| {
                                            debug!(service.log, "Failed to send peer dialed to router"); });
                            },
                            BehaviourEvent::PeerConnectedIncoming(_) | BehaviourEvent::PeerBanned(_) | BehaviourEvent::PeerUnbanned(_) => {
                                // No action required for these events.
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
                            BehaviourEvent::RPCFailed{id, peer_id} => {
                                let _ = service
                                    .router_send
                                    .send(RouterMessage::RPCFailed{ peer_id, request_id: id})
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
                                metrics::expose_receive_metrics(&message);

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
                        }
                        Libp2pEvent::NewListenAddr(multiaddr) => {
                            service.network_globals.listen_multiaddrs.write().push(multiaddr);
                        }
                        Libp2pEvent::ZeroListeners => {
                            let _ = shutdown_sender
                                .send(ShutdownReason::Failure("All listeners are closed. Unable to listen"))
                                .await
                                .map_err(|e| warn!(
                                    service.log,
                                    "failed to send a shutdown signal";
                                    "error" => %e
                                ));
                        }
                    }
                }
                Some(_) = &mut service.next_fork_update => {
                    let new_enr_fork_id = service.beacon_chain.enr_fork_id();

                    let fork_context = &service.fork_context;
                    if let Some(new_fork_name) = fork_context.from_context_bytes(new_enr_fork_id.fork_digest) {
                        info!(
                            service.log,
                            "Transitioned to new fork";
                            "old_fork" => ?fork_context.current_fork(),
                            "new_fork" => ?new_fork_name,
                        );
                        fork_context.update_current_fork(*new_fork_name);

                        service
                            .libp2p
                            .swarm
                            .behaviour_mut()
                            .update_fork_version(new_enr_fork_id.clone());
                        // Reinitialize the next_fork_update
                        service.next_fork_update = Box::pin(next_fork_delay(&service.beacon_chain).into());

                        // Set the next_unsubscribe delay.
                        let epoch_duration = service.beacon_chain.spec.seconds_per_slot * T::EthSpec::slots_per_epoch();
                        let unsubscribe_delay = Duration::from_secs(UNSUBSCRIBE_DELAY_EPOCHS * epoch_duration);
                        service.next_unsubscribe = Box::pin(Some(tokio::time::sleep(unsubscribe_delay)).into());
                        info!(service.log, "Network will unsubscribe from old fork gossip topics in a few epochs"; "remaining_epochs" => UNSUBSCRIBE_DELAY_EPOCHS);
                    } else {
                        crit!(service.log, "Unknown new enr fork id"; "new_fork_id" => ?new_enr_fork_id);
                    }

                }
                Some(_) = &mut service.next_unsubscribe => {
                    let new_enr_fork_id = service.beacon_chain.enr_fork_id();
                    service.libp2p.swarm.behaviour_mut().unsubscribe_from_fork_topics_except(new_enr_fork_id.fork_digest);
                    info!(service.log, "Unsubscribed from old fork topics");
                    service.next_unsubscribe = Box::pin(None.into());
                }
                Some(_) = &mut service.next_fork_subscriptions => {
                    if let Some((fork_name, _)) = service.beacon_chain.duration_to_next_fork() {
                        let fork_version = service.beacon_chain.spec.fork_version_for_name(fork_name);
                        let fork_digest = ChainSpec::compute_fork_digest(fork_version, service.beacon_chain.genesis_validators_root);
                        info!(service.log, "Subscribing to new fork topics");
                        service.libp2p.swarm.behaviour_mut().subscribe_new_fork_topics(fork_digest);
                    }
                    else {
                        error!(service.log, "Fork subscription scheduled but no fork scheduled");
                    }
                    service.next_fork_subscriptions = Box::pin(next_fork_subscriptions_delay(&service.beacon_chain).into());
                }
            }
            metrics::update_bandwidth_metrics(service.libp2p.bandwidth.clone());
        }
    }, "network");
}

/// Returns a `Sleep` that triggers after the next change in the beacon chain fork version.
/// If there is no scheduled fork, `None` is returned.
fn next_fork_delay<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> Option<tokio::time::Sleep> {
    beacon_chain
        .duration_to_next_fork()
        .map(|(_, until_fork)| tokio::time::sleep(until_fork))
}

/// Returns a `Sleep` that triggers `SUBSCRIBE_DELAY_SLOTS` before the next fork.
/// Returns `None` if there are no scheduled forks or we are already past `current_slot + SUBSCRIBE_DELAY_SLOTS > fork_slot`.
fn next_fork_subscriptions_delay<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> Option<tokio::time::Sleep> {
    if let Some((_, duration_to_fork)) = beacon_chain.duration_to_next_fork() {
        let duration_to_subscription = duration_to_fork.saturating_sub(Duration::from_secs(
            beacon_chain.spec.seconds_per_slot * SUBSCRIBE_DELAY_SLOTS,
        ));
        if !duration_to_subscription.is_zero() {
            return Some(tokio::time::sleep(duration_to_subscription));
        }
    }
    None
}

impl<T: BeaconChainTypes> Drop for NetworkService<T> {
    fn drop(&mut self) {
        // network thread is terminating
        let enrs = self.libp2p.swarm.behaviour_mut().enr_entries();
        debug!(
            self.log,
            "Persisting DHT to store";
            "Number of peers" => enrs.len(),
        );
        if let Err(e) = clear_dht::<T::EthSpec, T::HotStore, T::ColdStore>(self.store.clone()) {
            error!(self.log, "Failed to clear old DHT entries"; "error" => ?e);
        }
        // Still try to update new entries
        match persist_dht::<T::EthSpec, T::HotStore, T::ColdStore>(self.store.clone(), enrs) {
            Err(e) => error!(
                self.log,
                "Failed to persist DHT on drop";
                "error" => ?e
            ),
            Ok(_) => info!(
                self.log,
                "Saved DHT state";
            ),
        }

        // attempt to remove port mappings
        crate::nat::remove_mappings(self.upnp_mappings.0, self.upnp_mappings.1, &self.log);

        info!(self.log, "Network service shutdown");
    }
}
