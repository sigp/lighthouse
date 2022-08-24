use super::sync::manager::RequestId as SyncId;
use crate::persisted_dht::{clear_dht, load_dht, persist_dht};
use crate::router::{Router, RouterMessage};
use crate::subnet_service::SyncCommitteeService;
use crate::{error, metrics};
use crate::{
    subnet_service::{AttestationService, SubnetServiceMessage},
    NetworkConfig,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::channel::mpsc::Sender;
use futures::future::OptionFuture;
use futures::prelude::*;
use futures::StreamExt;
use lighthouse_network::service::Network;
use lighthouse_network::{prometheus_client::registry::Registry, MessageAcceptance};
use lighthouse_network::{
    rpc::{GoodbyeReason, RPCResponseErrorCode},
    Context, PeerAction, PeerRequestId, PubsubMessage, ReportSource, Request, Response, Subnet,
};
use lighthouse_network::{
    types::{GossipEncoding, GossipTopic},
    MessageId, NetworkEvent, NetworkGlobals, PeerId,
};
use slog::{crit, debug, error, info, o, trace, warn};
use std::{net::SocketAddr, pin::Pin, sync::Arc, time::Duration};
use store::HotColdDB;
use strum::IntoStaticStr;
use task_executor::ShutdownReason;
use tokio::sync::mpsc;
use tokio::time::Sleep;
use types::{
    ChainSpec, EthSpec, ForkContext, Slot, SubnetId, SyncCommitteeSubscription, SyncSubnetId,
    Unsigned, ValidatorSubscription,
};

mod tests;

/// The interval (in seconds) that various network metrics will update.
const METRIC_UPDATE_INTERVAL: u64 = 5;
/// Number of slots before the fork when we should subscribe to the new fork topics.
const SUBSCRIBE_DELAY_SLOTS: u64 = 2;
/// Delay after a fork where we unsubscribe from pre-fork topics.
const UNSUBSCRIBE_DELAY_EPOCHS: u64 = 2;
/// Size of the queue for validator subnet subscriptions. The number is chosen so that we may be
/// able to run tens of thousands of validators on one BN.
const VALIDATOR_SUBSCRIPTION_MESSAGE_QUEUE_SIZE: usize = 65_536;

/// Application level requests sent to the network.
#[derive(Debug, Clone, Copy)]
pub enum RequestId {
    Sync(SyncId),
    Router,
}

/// Types of messages that the network service can receive.
#[derive(Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum NetworkMessage<T: EthSpec> {
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
        msg: &'static str,
    },
    /// Disconnect an ban a peer, providing a reason.
    GoodbyePeer {
        peer_id: PeerId,
        reason: GoodbyeReason,
        source: ReportSource,
    },
}

/// Messages triggered by validators that may trigger a subscription to a subnet.
///
/// These messages can be very numerous with large validator counts (hundreds of thousands per
/// minute). Therefore we separate them from the separated from the `NetworkMessage` to provide
/// fairness regarding message processing.
#[derive(Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ValidatorSubscriptionMessage {
    /// Subscribes a list of validators to specific slots for attestation duties.
    AttestationSubscribe {
        subscriptions: Vec<ValidatorSubscription>,
    },
    SyncCommitteeSubscribe {
        subscriptions: Vec<SyncCommitteeSubscription>,
    },
}

#[derive(Clone)]
pub struct NetworkSenders<E: EthSpec> {
    network_send: mpsc::UnboundedSender<NetworkMessage<E>>,
    validator_subscription_send: mpsc::Sender<ValidatorSubscriptionMessage>,
}

pub struct NetworkReceivers<E: EthSpec> {
    pub network_recv: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    pub validator_subscription_recv: mpsc::Receiver<ValidatorSubscriptionMessage>,
}

impl<E: EthSpec> NetworkSenders<E> {
    pub fn new() -> (Self, NetworkReceivers<E>) {
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage<E>>();
        let (validator_subscription_send, validator_subscription_recv) =
            mpsc::channel(VALIDATOR_SUBSCRIPTION_MESSAGE_QUEUE_SIZE);
        let senders = Self {
            network_send,
            validator_subscription_send,
        };
        let receivers = NetworkReceivers {
            network_recv,
            validator_subscription_recv,
        };
        (senders, receivers)
    }

    pub fn network_send(&self) -> mpsc::UnboundedSender<NetworkMessage<E>> {
        self.network_send.clone()
    }

    pub fn validator_subscription_send(&self) -> mpsc::Sender<ValidatorSubscriptionMessage> {
        self.validator_subscription_send.clone()
    }
}

/// Service that handles communication between internal services and the `lighthouse_network` network service.
pub struct NetworkService<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    beacon_chain: Arc<BeaconChain<T>>,
    /// The underlying libp2p service that drives all the network interactions.
    libp2p: Network<RequestId, T::EthSpec>,
    /// An attestation and subnet manager service.
    attestation_service: AttestationService<T>,
    /// A sync committeee subnet manager service.
    sync_committee_service: SyncCommitteeService<T>,
    /// The receiver channel for lighthouse to communicate with the network service.
    network_recv: mpsc::UnboundedReceiver<NetworkMessage<T::EthSpec>>,
    /// The receiver channel for lighthouse to send validator subscription requests.
    validator_subscription_recv: mpsc::Receiver<ValidatorSubscriptionMessage>,
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
    /// Whether metrics are enabled or not.
    metrics_enabled: bool,
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
        gossipsub_registry: Option<&'_ mut Registry>,
    ) -> error::Result<(Arc<NetworkGlobals<T::EthSpec>>, NetworkSenders<T::EthSpec>)> {
        let network_log = executor.log().clone();
        // build the channels for external comms
        let (network_senders, network_recievers) = NetworkSenders::new();

        // try and construct UPnP port mappings if required.
        let upnp_config = crate::nat::UPnPConfig::from(config);
        let upnp_log = network_log.new(o!("service" => "UPnP"));
        let upnp_network_send = network_senders.network_send();
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

        // construct the libp2p service context
        let service_context = Context {
            config,
            enr_fork_id,
            fork_context: fork_context.clone(),
            chain_spec: &beacon_chain.spec,
            gossipsub_registry,
        };

        // launch libp2p service
        let (mut libp2p, network_globals) =
            Network::new(executor.clone(), service_context, &network_log).await?;

        // Repopulate the DHT with stored ENR's if discovery is not disabled.
        if !config.disable_discovery {
            let enrs_to_load = load_dht::<T::EthSpec, T::HotStore, T::ColdStore>(store.clone());
            debug!(
                network_log,
                "Loading peers into the routing table"; "peers" => enrs_to_load.len()
            );
            for enr in enrs_to_load {
                libp2p.add_enr(enr.clone());
            }
        }

        // launch derived network services

        // router task
        let router_send = Router::spawn(
            beacon_chain.clone(),
            network_globals.clone(),
            network_senders.network_send(),
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

        let NetworkReceivers {
            network_recv,
            validator_subscription_recv,
        } = network_recievers;

        // create the network service and spawn the task
        let network_log = network_log.new(o!("service" => "network"));
        let network_service = NetworkService {
            beacon_chain,
            libp2p,
            attestation_service,
            sync_committee_service,
            network_recv,
            validator_subscription_recv,
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
            metrics_enabled: config.metrics_enabled,
            metrics_update,
            gossipsub_parameter_update,
            fork_context,
            log: network_log,
        };

        network_service.spawn_service(executor);

        Ok((network_globals, network_senders))
    }

    /// Returns the required fork digests that gossipsub needs to subscribe to based on the current slot.
    ///
    /// For `current_slot < fork_slot`, this function returns both the pre-fork and post-fork
    /// digests since we should be subscribed to post fork topics before the fork.
    pub fn required_gossip_fork_digests(&self) -> Vec<[u8; 4]> {
        let fork_context = &self.fork_context;
        let spec = &self.beacon_chain.spec;
        let current_slot = self.beacon_chain.slot().unwrap_or(spec.genesis_slot);
        let current_fork = fork_context.current_fork();

        let mut result = vec![fork_context
            .to_context_bytes(current_fork)
            .unwrap_or_else(|| {
                panic!(
                    "{} fork bytes should exist as it's initialized in ForkContext",
                    current_fork
                )
            })];

        if let Some((next_fork, fork_epoch)) = spec.next_fork_epoch::<T::EthSpec>(current_slot) {
            if current_slot.saturating_add(Slot::new(SUBSCRIBE_DELAY_SLOTS))
                >= fork_epoch.start_slot(T::EthSpec::slots_per_epoch())
            {
                let next_fork_context_bytes =
                    fork_context.to_context_bytes(next_fork).unwrap_or_else(|| {
                        panic!(
                            "context bytes should exist as spec.next_fork_epoch({}) returned Some({})",
                            current_slot, next_fork
                        )
                    });
                result.push(next_fork_context_bytes);
            }
        }

        result
    }

    fn send_to_router(&mut self, msg: RouterMessage<T::EthSpec>) {
        if let Err(mpsc::error::SendError(msg)) = self.router_send.send(msg) {
            debug!(self.log, "Failed to send msg to router"; "msg" => ?msg);
        }
    }

    fn spawn_service(mut self, executor: task_executor::TaskExecutor) {
        let mut shutdown_sender = executor.shutdown_sender();

        // spawn on the current executor
        let service_fut = async move {
            loop {
                tokio::select! {
                    _ = self.metrics_update.tick(), if self.metrics_enabled => {
                        // update various network metrics
                        metrics::update_gossip_metrics::<T::EthSpec>(
                            self.libp2p.gossipsub(),
                            &self.network_globals,
                            );
                        // update sync metrics
                        metrics::update_sync_metrics(&self.network_globals);
                    }

                    _ = self.gossipsub_parameter_update.tick() => self.update_gossipsub_parameters(),

                    // handle a message sent to the network
                    Some(msg) = self.network_recv.recv() => self.on_network_msg(msg, &mut shutdown_sender).await,

                    // handle a message from a validator requesting a subscription to a subnet
                    Some(msg) = self.validator_subscription_recv.recv() => self.on_validator_subscription_msg(msg).await,

                    // process any attestation service events
                    Some(msg) = self.attestation_service.next() => self.on_attestation_service_msg(msg),

                    // process any sync committee service events
                    Some(msg) = self.sync_committee_service.next() => self.on_sync_committee_service_message(msg),

                    event = self.libp2p.next_event() => self.on_libp2p_event(event, &mut shutdown_sender).await,

                    Some(_) = &mut self.next_fork_update => self.update_next_fork(),

                    Some(_) = &mut self.next_unsubscribe => {
                        let new_enr_fork_id = self.beacon_chain.enr_fork_id();
                        self.libp2p.unsubscribe_from_fork_topics_except(new_enr_fork_id.fork_digest);
                        info!(self.log, "Unsubscribed from old fork topics");
                        self.next_unsubscribe = Box::pin(None.into());
                    }

                    Some(_) = &mut self.next_fork_subscriptions => {
                        if let Some((fork_name, _)) = self.beacon_chain.duration_to_next_fork() {
                            let fork_version = self.beacon_chain.spec.fork_version_for_name(fork_name);
                            let fork_digest = ChainSpec::compute_fork_digest(fork_version, self.beacon_chain.genesis_validators_root);
                            info!(self.log, "Subscribing to new fork topics");
                            self.libp2p.subscribe_new_fork_topics(fork_digest);
                            self.next_fork_subscriptions = Box::pin(None.into());
                        }
                        else {
                            error!(self.log, "Fork subscription scheduled but no fork scheduled");
                        }
                    }
                }
                metrics::update_bandwidth_metrics(self.libp2p.bandwidth.clone());
            }
        };
        executor.spawn(service_fut, "network");
    }

    /// Handle an event received from the network.
    async fn on_libp2p_event(
        &mut self,
        ev: NetworkEvent<RequestId, T::EthSpec>,
        shutdown_sender: &mut Sender<ShutdownReason>,
    ) {
        match ev {
            NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                self.send_to_router(RouterMessage::PeerDialed(peer_id));
            }
            NetworkEvent::PeerConnectedIncoming(_)
            | NetworkEvent::PeerBanned(_)
            | NetworkEvent::PeerUnbanned(_) => {
                // No action required for these events.
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                self.send_to_router(RouterMessage::PeerDisconnected(peer_id));
            }
            NetworkEvent::RequestReceived {
                peer_id,
                id,
                request,
            } => {
                self.send_to_router(RouterMessage::RPCRequestReceived {
                    peer_id,
                    id,
                    request,
                });
            }
            NetworkEvent::ResponseReceived {
                peer_id,
                id,
                response,
            } => {
                self.send_to_router(RouterMessage::RPCResponseReceived {
                    peer_id,
                    request_id: id,
                    response,
                });
            }
            NetworkEvent::RPCFailed { id, peer_id } => {
                self.send_to_router(RouterMessage::RPCFailed {
                    peer_id,
                    request_id: id,
                });
            }
            NetworkEvent::StatusPeer(peer_id) => {
                self.send_to_router(RouterMessage::StatusPeer(peer_id));
            }
            NetworkEvent::PubsubMessage {
                id,
                source,
                message,
                ..
            } => {
                match message {
                    // attestation information gets processed in the attestation service
                    PubsubMessage::Attestation(ref subnet_and_attestation) => {
                        let subnet = subnet_and_attestation.0;
                        let attestation = &subnet_and_attestation.1;
                        // checks if we have an aggregator for the slot. If so, we should process
                        // the attestation, else we just just propagate the Attestation.
                        let should_process = self
                            .attestation_service
                            .should_process_attestation(subnet, attestation);
                        self.send_to_router(RouterMessage::PubsubMessage(
                            id,
                            source,
                            message,
                            should_process,
                        ));
                    }
                    _ => {
                        // all else is sent to the router
                        self.send_to_router(RouterMessage::PubsubMessage(
                            id, source, message, true,
                        ));
                    }
                }
            }
            NetworkEvent::NewListenAddr(multiaddr) => {
                self.network_globals
                    .listen_multiaddrs
                    .write()
                    .push(multiaddr);
            }
            NetworkEvent::ZeroListeners => {
                let _ = shutdown_sender
                    .send(ShutdownReason::Failure(
                        "All listeners are closed. Unable to listen",
                    ))
                    .await
                    .map_err(|e| {
                        warn!(
                            self.log,
                            "failed to send a shutdown signal";
                            "error" => %e
                        )
                    });
            }
        }
    }

    /// Handle a message sent to the network service.
    async fn on_network_msg(
        &mut self,
        msg: NetworkMessage<T::EthSpec>,
        shutdown_sender: &mut Sender<ShutdownReason>,
    ) {
        metrics::inc_counter_vec(&metrics::NETWORK_RECEIVE_EVENTS, &[(&msg).into()]);
        let _timer = metrics::start_timer_vec(&metrics::NETWORK_RECEIVE_TIMES, &[(&msg).into()]);

        match msg {
            NetworkMessage::SendRequest {
                peer_id,
                request,
                request_id,
            } => {
                self.libp2p.send_request(peer_id, request_id, request);
            }
            NetworkMessage::SendResponse {
                peer_id,
                response,
                id,
            } => {
                self.libp2p.send_response(peer_id, id, response);
            }
            NetworkMessage::SendErrorResponse {
                peer_id,
                error,
                id,
                reason,
            } => {
                self.libp2p.send_error_reponse(peer_id, id, error, reason);
            }
            NetworkMessage::UPnPMappingEstablished {
                tcp_socket,
                udp_socket,
            } => {
                self.upnp_mappings = (tcp_socket.map(|s| s.port()), udp_socket.map(|s| s.port()));
                // If there is an external TCP port update, modify our local ENR.
                if let Some(tcp_socket) = tcp_socket {
                    if let Err(e) = self
                        .libp2p
                        .discovery_mut()
                        .update_enr_tcp_port(tcp_socket.port())
                    {
                        warn!(self.log, "Failed to update ENR"; "error" => e);
                    }
                }
                // if the discovery service is not auto-updating, update it with the
                // UPnP mappings
                if !self.discovery_auto_update {
                    if let Some(udp_socket) = udp_socket {
                        if let Err(e) = self
                            .libp2p
                            .discovery_mut()
                            .update_enr_udp_socket(udp_socket)
                        {
                            warn!(self.log, "Failed to update ENR"; "error" => e);
                        }
                    }
                }
            }
            NetworkMessage::ValidationResult {
                propagation_source,
                message_id,
                validation_result,
            } => {
                trace!(self.log, "Propagating gossipsub message";
                    "propagation_peer" => ?propagation_source,
                    "message_id" => %message_id,
                    "validation_result" => ?validation_result
                );
                self.libp2p.report_message_validation_result(
                    &propagation_source,
                    message_id,
                    validation_result,
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
                    self.log,
                    "Sending pubsub messages";
                    "count" => messages.len(),
                    "topics" => ?topic_kinds
                );
                self.libp2p.publish(messages);
            }
            NetworkMessage::ReportPeer {
                peer_id,
                action,
                source,
                msg,
            } => self.libp2p.report_peer(&peer_id, action, source, msg),
            NetworkMessage::GoodbyePeer {
                peer_id,
                reason,
                source,
            } => self.libp2p.goodbye_peer(&peer_id, reason, source),
            NetworkMessage::SubscribeCoreTopics => {
                if self.shutdown_after_sync {
                    if let Err(e) = shutdown_sender
                        .send(ShutdownReason::Success(
                            "Beacon node completed sync. \
                             Shutting down as --shutdown-after-sync flag is enabled",
                        ))
                        .await
                    {
                        warn!(
                            self.log,
                            "failed to send a shutdown signal";
                            "error" => %e
                        )
                    }
                    return;
                }
                let mut subscribed_topics: Vec<GossipTopic> = vec![];
                for topic_kind in lighthouse_network::types::CORE_TOPICS.iter() {
                    for fork_digest in self.required_gossip_fork_digests() {
                        let topic = GossipTopic::new(
                            topic_kind.clone(),
                            GossipEncoding::default(),
                            fork_digest,
                        );
                        if self.libp2p.subscribe(topic.clone()) {
                            subscribed_topics.push(topic);
                        } else {
                            warn!(self.log, "Could not subscribe to topic"; "topic" => %topic);
                        }
                    }
                }

                // If we are to subscribe to all subnets we do it here
                if self.subscribe_all_subnets {
                    for subnet_id in 0..<<T as BeaconChainTypes>::EthSpec as EthSpec>::SubnetBitfieldLength::to_u64() {
                        let subnet = Subnet::Attestation(SubnetId::new(subnet_id));
                        // Update the ENR bitfield
                        self.libp2p.update_enr_subnet(subnet, true);
                        for fork_digest in self.required_gossip_fork_digests() {
                            let topic = GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                            if self.libp2p.subscribe(topic.clone()) {
                                subscribed_topics.push(topic);
                            } else {
                                warn!(self.log, "Could not subscribe to topic"; "topic" => %topic);
                            }
                        }
                    }
                    let subnet_max = <<T as BeaconChainTypes>::EthSpec as EthSpec>::SyncCommitteeSubnetCount::to_u64();
                    for subnet_id in 0..subnet_max {
                        let subnet = Subnet::SyncCommittee(SyncSubnetId::new(subnet_id));
                        // Update the ENR bitfield
                        self.libp2p.update_enr_subnet(subnet, true);
                        for fork_digest in self.required_gossip_fork_digests() {
                            let topic = GossipTopic::new(
                                subnet.into(),
                                GossipEncoding::default(),
                                fork_digest,
                            );
                            if self.libp2p.subscribe(topic.clone()) {
                                subscribed_topics.push(topic);
                            } else {
                                warn!(self.log, "Could not subscribe to topic"; "topic" => %topic);
                            }
                        }
                    }
                }

                if !subscribed_topics.is_empty() {
                    info!(
                        self.log,
                        "Subscribed to topics";
                        "topics" => ?subscribed_topics.into_iter().map(|topic| format!("{}", topic)).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    /// Handle a message sent to the network service.
    async fn on_validator_subscription_msg(&mut self, msg: ValidatorSubscriptionMessage) {
        match msg {
            ValidatorSubscriptionMessage::AttestationSubscribe { subscriptions } => {
                if let Err(e) = self
                    .attestation_service
                    .validator_subscriptions(subscriptions)
                {
                    warn!(self.log, "Attestation validator subscription failed"; "error" => e);
                }
            }
            ValidatorSubscriptionMessage::SyncCommitteeSubscribe { subscriptions } => {
                if let Err(e) = self
                    .sync_committee_service
                    .validator_subscriptions(subscriptions)
                {
                    warn!(self.log, "Sync committee calidator subscription failed"; "error" => e);
                }
            }
        }
    }

    fn update_gossipsub_parameters(&mut self) {
        if let Ok(slot) = self.beacon_chain.slot() {
            let active_validators_opt = self
                .beacon_chain
                .canonical_head
                .cached_head()
                .active_validator_count();
            if let Some(active_validators) = active_validators_opt {
                if self
                    .libp2p
                    .update_gossipsub_parameters(active_validators, slot)
                    .is_err()
                {
                    error!(
                        self.log,
                        "Failed to update gossipsub parameters";
                        "active_validators" => active_validators
                    );
                }
            } else {
                // This scenario will only happen if the caches on the cached canonical head aren't
                // built. That should never be the case.
                error!(
                    self.log,
                    "Active validator count unavailable";
                    "info" => "please report this bug"
                );
            }
        }
    }

    fn on_attestation_service_msg(&mut self, msg: SubnetServiceMessage) {
        match msg {
            SubnetServiceMessage::Subscribe(subnet) => {
                for fork_digest in self.required_gossip_fork_digests() {
                    let topic =
                        GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                    self.libp2p.subscribe(topic);
                }
            }
            SubnetServiceMessage::Unsubscribe(subnet) => {
                for fork_digest in self.required_gossip_fork_digests() {
                    let topic =
                        GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                    self.libp2p.unsubscribe(topic);
                }
            }
            SubnetServiceMessage::EnrAdd(subnet) => {
                self.libp2p.update_enr_subnet(subnet, true);
            }
            SubnetServiceMessage::EnrRemove(subnet) => {
                self.libp2p.update_enr_subnet(subnet, false);
            }
            SubnetServiceMessage::DiscoverPeers(subnets_to_discover) => {
                self.libp2p.discover_subnet_peers(subnets_to_discover);
            }
        }
    }

    fn on_sync_committee_service_message(&mut self, msg: SubnetServiceMessage) {
        match msg {
            SubnetServiceMessage::Subscribe(subnet) => {
                for fork_digest in self.required_gossip_fork_digests() {
                    let topic =
                        GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                    self.libp2p.subscribe(topic);
                }
            }
            SubnetServiceMessage::Unsubscribe(subnet) => {
                for fork_digest in self.required_gossip_fork_digests() {
                    let topic =
                        GossipTopic::new(subnet.into(), GossipEncoding::default(), fork_digest);
                    self.libp2p.unsubscribe(topic);
                }
            }
            SubnetServiceMessage::EnrAdd(subnet) => {
                self.libp2p.update_enr_subnet(subnet, true);
            }
            SubnetServiceMessage::EnrRemove(subnet) => {
                self.libp2p.update_enr_subnet(subnet, false);
            }
            SubnetServiceMessage::DiscoverPeers(subnets_to_discover) => {
                self.libp2p.discover_subnet_peers(subnets_to_discover);
            }
        }
    }

    fn update_next_fork(&mut self) {
        let new_enr_fork_id = self.beacon_chain.enr_fork_id();

        let fork_context = &self.fork_context;
        if let Some(new_fork_name) = fork_context.from_context_bytes(new_enr_fork_id.fork_digest) {
            info!(
                self.log,
                "Transitioned to new fork";
                "old_fork" => ?fork_context.current_fork(),
                "new_fork" => ?new_fork_name,
            );
            fork_context.update_current_fork(*new_fork_name);

            self.libp2p.update_fork_version(new_enr_fork_id);
            // Reinitialize the next_fork_update
            self.next_fork_update = Box::pin(next_fork_delay(&self.beacon_chain).into());

            // Set the next_unsubscribe delay.
            let epoch_duration =
                self.beacon_chain.spec.seconds_per_slot * T::EthSpec::slots_per_epoch();
            let unsubscribe_delay = Duration::from_secs(UNSUBSCRIBE_DELAY_EPOCHS * epoch_duration);

            // Update the `next_fork_subscriptions` timer if the next fork is known.
            self.next_fork_subscriptions =
                Box::pin(next_fork_subscriptions_delay(&self.beacon_chain).into());
            self.next_unsubscribe = Box::pin(Some(tokio::time::sleep(unsubscribe_delay)).into());
            info!(self.log, "Network will unsubscribe from old fork gossip topics in a few epochs"; "remaining_epochs" => UNSUBSCRIBE_DELAY_EPOCHS);
        } else {
            crit!(self.log, "Unknown new enr fork id"; "new_fork_id" => ?new_enr_fork_id);
        }
    }
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
        let enrs = self.libp2p.enr_entries();
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
