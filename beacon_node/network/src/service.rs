use crate::NetworkConfig;
use crate::metrics;
use crate::nat;
use crate::network_beacon_processor::InvalidBlockStorage;
use crate::persisted_dht::{clear_dht, load_dht, persist_dht};
use crate::router::{Router, RouterMessage};
use crate::subnet_service::{SubnetService, SubnetServiceMessage, Subscription};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use beacon_processor::BeaconProcessorSend;
use futures::channel::mpsc::Sender;
use futures::future::OptionFuture;
use futures::prelude::*;

use lighthouse_network::Enr;
use lighthouse_network::identity::Keypair;
use lighthouse_network::rpc::InboundRequestId;
use lighthouse_network::rpc::RequestType;
use lighthouse_network::rpc::methods::RpcResponse;
use lighthouse_network::service::Network;
use lighthouse_network::types::GossipKind;
use lighthouse_network::{
    Context, PeerAction, PubsubMessage, ReportSource, Response, Subnet,
    rpc::{GoodbyeReason, RpcErrorResponse},
};
use lighthouse_network::{MessageAcceptance, prometheus_client::registry::Registry};
use lighthouse_network::{
    MessageId, NetworkEvent, NetworkGlobals, PeerId,
    service::api_types::AppRequestId,
    types::{GossipEncoding, GossipTopic, core_topics_to_subscribe},
};
use logging::crit;
use std::collections::BTreeSet;
use std::{collections::HashSet, pin::Pin, sync::Arc, time::Duration};
use store::HotColdDB;
use strum::IntoStaticStr;
use task_executor::ShutdownReason;
use tokio::sync::mpsc;
use tokio::time::Sleep;
use tracing::{debug, error, info, trace, warn};
use types::{
    EthSpec, ForkContext, Slot, SubnetId, SyncCommitteeSubscription, SyncSubnetId, Unsigned,
    ValidatorSubscription,
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

/// Types of messages that the network service can receive.
#[derive(Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum NetworkMessage<E: EthSpec> {
    /// Subscribes the beacon node to the core gossipsub topics. We do this when we are either
    /// synced or close to the head slot.
    SubscribeCoreTopics,
    /// Send an RPC request to the libp2p service.
    SendRequest {
        peer_id: PeerId,
        request: RequestType<E>,
        app_request_id: AppRequestId,
    },
    /// Send a successful Response to the libp2p service.
    SendResponse {
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        response: Response<E>,
    },
    /// Sends an error response to an RPC request.
    SendErrorResponse {
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        error: RpcErrorResponse,
        reason: String,
    },
    /// Publish a list of messages to the gossipsub protocol.
    Publish { messages: Vec<PubsubMessage<E>> },
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
    /// Connect to a trusted peer and try to maintain the connection.
    ConnectTrustedPeer(Enr),
    /// Disconnect from a trusted peer and remove it from the `trusted_peers` mapping.
    DisconnectTrustedPeer(Enr),
    /// Custody group count changed due to a change in validators' weight.
    /// Subscribe to new subnets and update ENR metadata.
    CustodyCountChanged {
        new_custody_group_count: u64,
        sampling_count: u64,
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
        subscriptions: BTreeSet<ValidatorSubscription>,
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
    libp2p: Network<T::EthSpec>,
    /// An attestation and sync committee subnet manager service.
    subnet_service: SubnetService<T>,
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
    /// A delay that expires when the fork digest changes.
    next_digest_update: Pin<Box<OptionFuture<Sleep>>>,
    /// A delay that expires when we need to subscribe to a new set of topics.
    next_topic_subscriptions: Pin<Box<OptionFuture<Sleep>>>,
    /// A delay that expires when we need to unsubscribe from old topics.
    next_unsubscribe: Pin<Box<OptionFuture<Sleep>>>,
    /// Shutdown beacon node after sync is complete.
    shutdown_after_sync: bool,
    /// Whether metrics are enabled or not.
    metrics_enabled: bool,
    /// A timer for updating various network metrics.
    metrics_update: tokio::time::Interval,
    /// gossipsub_parameter_update timer
    gossipsub_parameter_update: tokio::time::Interval,
    /// Provides fork specific info.
    fork_context: Arc<ForkContext>,
}

impl<T: BeaconChainTypes> NetworkService<T> {
    async fn build(
        beacon_chain: Arc<BeaconChain<T>>,
        config: Arc<NetworkConfig>,
        executor: task_executor::TaskExecutor,
        libp2p_registry: Option<&'_ mut Registry>,
        beacon_processor_send: BeaconProcessorSend<T::EthSpec>,
        local_keypair: Keypair,
    ) -> Result<
        (
            NetworkService<T>,
            Arc<NetworkGlobals<T::EthSpec>>,
            NetworkSenders<T::EthSpec>,
        ),
        String,
    > {
        // build the channels for external comms
        let (network_senders, network_receivers) = NetworkSenders::new();

        #[cfg(feature = "disable-backfill")]
        warn!("Backfill is disabled. DO NOT RUN IN PRODUCTION");

        if let (true, false, Some(v4)) = (
            config.upnp_enabled,
            config.disable_discovery,
            config.listen_addrs().v4(),
        ) {
            let v4 = v4.clone();
            executor.spawn(
                async move {
                    info!("UPnP Attempting to initialise routes");
                    if let Err(e) = nat::construct_upnp_mappings(v4.addr, v4.disc_port).await {
                        info!(error = %e, "Could not UPnP map Discovery port");
                    }
                },
                "UPnP",
            );
        }

        // get a reference to the beacon chain store
        let store = beacon_chain.store.clone();

        // build the current enr_fork_id for adding to our local ENR
        let enr_fork_id = beacon_chain.enr_fork_id();

        // keep track of when our fork_id needs to be updated
        let next_digest_update = Box::pin(next_digest_delay(&beacon_chain).into());
        // topics change when the fork digest changes
        let next_topic_subscriptions =
            Box::pin(next_topic_subscriptions_delay(&beacon_chain).into());
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

        // construct the libp2p service context
        let service_context = Context {
            config: config.clone(),
            enr_fork_id,
            fork_context: fork_context.clone(),
            chain_spec: beacon_chain.spec.clone(),
            libp2p_registry,
        };

        // launch libp2p service
        let (mut libp2p, network_globals) = Network::new(
            executor.clone(),
            service_context,
            beacon_chain
                .data_availability_checker
                .custody_context()
                .custody_group_count_at_head(&beacon_chain.spec),
            local_keypair,
        )
        .await?;

        // Repopulate the DHT with stored ENR's if discovery is not disabled.
        if !config.disable_discovery {
            let enrs_to_load = load_dht::<T::EthSpec, T::HotStore, T::ColdStore>(store.clone());
            debug!(
                peers = enrs_to_load.len(),
                "Loading peers into the routing table"
            );
            for enr in enrs_to_load {
                libp2p.add_enr(enr.clone());
            }
        }

        let invalid_block_storage = config
            .invalid_block_storage
            .clone()
            .map(InvalidBlockStorage::Enabled)
            .unwrap_or(InvalidBlockStorage::Disabled);

        // launch derived network services

        // router task
        let router_send = Router::spawn(
            beacon_chain.clone(),
            network_globals.clone(),
            network_senders.network_send(),
            executor.clone(),
            invalid_block_storage,
            beacon_processor_send,
            fork_context.clone(),
        )?;

        // attestation and sync committee subnet service
        let subnet_service = SubnetService::new(
            beacon_chain.clone(),
            network_globals.local_enr().node_id(),
            &config,
        );

        // create a timer for updating network metrics
        let metrics_update = tokio::time::interval(Duration::from_secs(METRIC_UPDATE_INTERVAL));

        // create a timer for updating gossipsub parameters
        let gossipsub_parameter_update = tokio::time::interval(Duration::from_secs(60));

        let NetworkReceivers {
            network_recv,
            validator_subscription_recv,
        } = network_receivers;

        // create the network service and spawn the task
        let network_service = NetworkService {
            beacon_chain,
            libp2p,
            subnet_service,
            network_recv,
            validator_subscription_recv,
            router_send,
            store,
            network_globals: network_globals.clone(),
            next_digest_update,
            next_topic_subscriptions,
            next_unsubscribe,
            shutdown_after_sync: config.shutdown_after_sync,
            metrics_enabled: config.metrics_enabled,
            metrics_update,
            gossipsub_parameter_update,
            fork_context,
        };

        Ok((network_service, network_globals, network_senders))
    }

    #[allow(clippy::type_complexity)]
    pub async fn start(
        beacon_chain: Arc<BeaconChain<T>>,
        config: Arc<NetworkConfig>,
        executor: task_executor::TaskExecutor,
        libp2p_registry: Option<&'_ mut Registry>,
        beacon_processor_send: BeaconProcessorSend<T::EthSpec>,
        local_keypair: Keypair,
    ) -> Result<(Arc<NetworkGlobals<T::EthSpec>>, NetworkSenders<T::EthSpec>), String> {
        let (network_service, network_globals, network_senders) = Self::build(
            beacon_chain,
            config,
            executor.clone(),
            libp2p_registry,
            beacon_processor_send,
            local_keypair,
        )
        .await?;

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
        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

        let mut result = vec![fork_context.context_bytes(current_epoch)];

        if let Some(next_digest_epoch) = spec.next_digest_epoch(current_epoch)
            && current_slot.saturating_add(Slot::new(SUBSCRIBE_DELAY_SLOTS))
                >= next_digest_epoch.start_slot(T::EthSpec::slots_per_epoch())
        {
            let next_digest = fork_context.context_bytes(next_digest_epoch);
            result.push(next_digest);
        }

        result
    }

    fn send_to_router(&mut self, msg: RouterMessage<T::EthSpec>) {
        if let Err(mpsc::error::SendError(msg)) = self.router_send.send(msg) {
            debug!(?msg, "Failed to send msg to router");
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

                    // process any subnet service events
                    Some(msg) = self.subnet_service.next() => self.on_subnet_service_msg(msg),

                    event = self.libp2p.next_event() => self.on_libp2p_event(event, &mut shutdown_sender).await,

                    Some(_) = &mut self.next_digest_update => self.update_next_fork_digest(),

                    Some(_) = &mut self.next_unsubscribe => {
                        let new_enr_fork_id = self.beacon_chain.enr_fork_id();
                        self.libp2p.unsubscribe_from_fork_topics_except(new_enr_fork_id.fork_digest);
                        info!("Unsubscribed from old fork topics");
                        self.next_unsubscribe = Box::pin(None.into());
                    }

                    Some(_) = &mut self.next_topic_subscriptions => {
                        if let Some((epoch, _)) = self.beacon_chain.duration_to_next_digest() {
                            let fork_name = self.beacon_chain.spec.fork_name_at_epoch(epoch);
                            let fork_digest = self.beacon_chain.compute_fork_digest(epoch);
                            info!("Subscribing to new fork topics");
                            self.libp2p.subscribe_new_fork_topics(fork_name, fork_digest);
                            self.next_topic_subscriptions = Box::pin(None.into());
                        }
                        else {
                            error!( "Fork subscription scheduled but no fork scheduled");
                        }
                    }
                }
            }
        };
        executor.spawn(service_fut, "network");
    }

    /// Handle an event received from the network.
    async fn on_libp2p_event(
        &mut self,
        ev: NetworkEvent<T::EthSpec>,
        shutdown_sender: &mut Sender<ShutdownReason>,
    ) {
        match ev {
            NetworkEvent::PeerConnectedOutgoing(peer_id) => {
                self.send_to_router(RouterMessage::StatusPeer(peer_id));
            }
            NetworkEvent::PeerConnectedIncoming(_) => {
                // No action required for this event.
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                self.send_to_router(RouterMessage::PeerDisconnected(peer_id));
            }
            NetworkEvent::PeerUpdatedCustodyGroupCount(peer_id) => {
                self.send_to_router(RouterMessage::PeerUpdatedCustodyGroupCount(peer_id));
            }
            NetworkEvent::RequestReceived {
                peer_id,
                inbound_request_id,
                request_type,
            } => {
                self.send_to_router(RouterMessage::RPCRequestReceived {
                    peer_id,
                    inbound_request_id,
                    request_type,
                });
            }
            NetworkEvent::ResponseReceived {
                peer_id,
                app_request_id,
                response,
            } => {
                self.send_to_router(RouterMessage::RPCResponseReceived {
                    peer_id,
                    app_request_id,
                    response,
                });
            }
            NetworkEvent::RPCFailed {
                app_request_id,
                peer_id,
                error,
            } => {
                self.send_to_router(RouterMessage::RPCFailed {
                    peer_id,
                    app_request_id,
                    error,
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
                        let subnet_id = subnet_and_attestation.0;
                        let attestation = &subnet_and_attestation.1;
                        // checks if we have an aggregator for the slot. If so, we should process
                        // the attestation, else we just just propagate the Attestation.
                        let should_process = self.subnet_service.should_process_attestation(
                            Subnet::Attestation(subnet_id),
                            &attestation.data,
                        );
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
                            error = %e,
                            "failed to send a shutdown signal"
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
                app_request_id,
            } => {
                if let Err((app_request_id, error)) =
                    self.libp2p.send_request(peer_id, app_request_id, request)
                {
                    self.send_to_router(RouterMessage::RPCFailed {
                        peer_id,
                        app_request_id,
                        error,
                    });
                }
            }
            NetworkMessage::SendResponse {
                peer_id,
                inbound_request_id,
                response,
            } => {
                self.libp2p
                    .send_response(peer_id, inbound_request_id, response);
            }
            NetworkMessage::SendErrorResponse {
                peer_id,
                error,
                inbound_request_id,
                reason,
            } => self.libp2p.send_response(
                peer_id,
                inbound_request_id,
                RpcResponse::Error(error, reason.into()),
            ),
            NetworkMessage::ValidationResult {
                propagation_source,
                message_id,
                validation_result,
            } => {
                trace!(                    propagation_peer = ?propagation_source,
                    %message_id,
                    ?validation_result, "Propagating gossipsub message"
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
                    count = messages.len(),
                    topics = ?topic_kinds,
                    "Sending pubsub messages"
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
            NetworkMessage::ConnectTrustedPeer(enr) => {
                self.libp2p.dial_trusted_peer(enr);
            }
            NetworkMessage::DisconnectTrustedPeer(enr) => {
                self.libp2p.remove_trusted_peer(enr);
            }
            NetworkMessage::SubscribeCoreTopics => {
                if self.subscribed_core_topics() {
                    return;
                }

                if self.shutdown_after_sync {
                    if let Err(e) = shutdown_sender
                        .send(ShutdownReason::Success(
                            "Beacon node completed sync. \
                             Shutting down as --shutdown-after-sync flag is enabled",
                        ))
                        .await
                    {
                        warn!(
                            error = %e,
                            "failed to send a shutdown signal"
                        )
                    }
                    return;
                }

                let mut subscribed_topics: Vec<GossipTopic> = vec![];
                for topic_kind in core_topics_to_subscribe::<T::EthSpec>(
                    self.fork_context.current_fork_name(),
                    &self.network_globals.as_topic_config(),
                    &self.fork_context.spec,
                ) {
                    for fork_digest in self.required_gossip_fork_digests() {
                        let topic = GossipTopic::new(
                            topic_kind.clone(),
                            GossipEncoding::default(),
                            fork_digest,
                        );
                        if self.libp2p.subscribe(topic.clone()) {
                            subscribed_topics.push(topic);
                        } else {
                            warn!(%topic, "Could not subscribe to topic");
                        }
                    }
                }

                // If we are to subscribe to all subnets we do it here
                if self.network_globals.config.subscribe_all_subnets {
                    for subnet_id in 0..<<T as BeaconChainTypes>::EthSpec as EthSpec>::SubnetBitfieldLength::to_u64() {
                        let subnet = Subnet::Attestation(SubnetId::new(subnet_id));
                        // Update the ENR bitfield
                        self.libp2p.update_enr_subnet(subnet, true);
                    }
                    let subnet_max = <<T as BeaconChainTypes>::EthSpec as EthSpec>::SyncCommitteeSubnetCount::to_u64();
                    for subnet_id in 0..subnet_max {
                        let subnet = Subnet::SyncCommittee(SyncSubnetId::new(subnet_id));
                        // Update the ENR bitfield
                        self.libp2p.update_enr_subnet(subnet, true);
                    }
                }

                if !subscribed_topics.is_empty() {
                    info!(
                        topics = ?subscribed_topics.into_iter().map(|topic| format!("{}", topic)).collect::<Vec<_>>(),
                        "Subscribed to topics"
                    );
                }
            }
            NetworkMessage::CustodyCountChanged {
                new_custody_group_count,
                sampling_count,
            } => {
                // subscribe to `sampling_count` subnets
                self.libp2p
                    .subscribe_new_data_column_subnets(sampling_count);
                if self
                    .network_globals
                    .config
                    .advertise_false_custody_group_count
                    .is_none()
                {
                    self.libp2p.update_enr_cgc(new_custody_group_count);
                }
            }
        }
    }

    /// Handle a message sent to the network service.
    async fn on_validator_subscription_msg(&mut self, msg: ValidatorSubscriptionMessage) {
        match msg {
            ValidatorSubscriptionMessage::AttestationSubscribe { subscriptions } => {
                let subscriptions = subscriptions.into_iter().map(Subscription::Attestation);
                self.subnet_service.validator_subscriptions(subscriptions)
            }
            ValidatorSubscriptionMessage::SyncCommitteeSubscribe { subscriptions } => {
                let subscriptions = subscriptions.into_iter().map(Subscription::SyncCommittee);
                self.subnet_service.validator_subscriptions(subscriptions)
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
                    error!(active_validators, "Failed to update gossipsub parameters");
                }
            } else {
                // This scenario will only happen if the caches on the cached canonical head aren't
                // built. That should never be the case.
                error!(
                    info = "please report this bug",
                    "Active validator count unavailable"
                );
            }
        }
    }

    fn on_subnet_service_msg(&mut self, msg: SubnetServiceMessage) {
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
            SubnetServiceMessage::EnrRemove(sync_subnet_id) => {
                self.libp2p
                    .update_enr_subnet(Subnet::SyncCommittee(sync_subnet_id), false);
            }
            SubnetServiceMessage::DiscoverPeers(subnets_to_discover) => {
                self.libp2p.discover_subnet_peers(subnets_to_discover);
            }
        }
    }

    fn update_next_fork_digest(&mut self) {
        let new_enr_fork_id = self.beacon_chain.enr_fork_id();
        // if we are unable to read the slot clock we assume that it is prior to genesis
        let current_epoch = self.beacon_chain.epoch().unwrap_or(
            self.beacon_chain
                .spec
                .genesis_slot
                .epoch(T::EthSpec::slots_per_epoch()),
        );
        let new_fork_digest = new_enr_fork_id.fork_digest;

        let fork_context = &self.fork_context;
        if let Some(new_fork_name) = fork_context.get_fork_from_context_bytes(new_fork_digest) {
            if fork_context.current_fork_name() == *new_fork_name {
                info!(
                    epoch = ?current_epoch,
                    "BPO Fork Triggered"
                )
            } else {
                info!(
                    old_fork = ?fork_context.current_fork_name(),
                    new_fork = ?new_fork_name,
                    "Transitioned to new fork"
                );
                new_fork_name.fork_ascii();
            }

            fork_context.update_current_fork(*new_fork_name, new_fork_digest, current_epoch);
            if self.beacon_chain.spec.is_peer_das_scheduled() {
                let next_fork_digest = fork_context
                    .next_fork_digest()
                    .unwrap_or_else(|| fork_context.current_fork_digest());
                self.libp2p.update_nfd(next_fork_digest);
            }

            self.libp2p.update_fork_version(new_enr_fork_id);
            // Reinitialize the next_fork_update
            self.next_digest_update = Box::pin(next_digest_delay(&self.beacon_chain).into());

            // Set the next_unsubscribe delay.
            let epoch_duration =
                self.beacon_chain.spec.seconds_per_slot * T::EthSpec::slots_per_epoch();
            let unsubscribe_delay = Duration::from_secs(UNSUBSCRIBE_DELAY_EPOCHS * epoch_duration);

            // Update the `next_topic_subscriptions` timer if the next change in the fork digest is known.
            self.next_topic_subscriptions =
                Box::pin(next_topic_subscriptions_delay(&self.beacon_chain).into());
            self.next_unsubscribe = Box::pin(Some(tokio::time::sleep(unsubscribe_delay)).into());
            info!(
                remaining_epochs = UNSUBSCRIBE_DELAY_EPOCHS,
                "Network will unsubscribe from old fork gossip topics in a few epochs"
            );

            // Remove topic weight from old fork topics to prevent peers that left on the mesh on
            // old topics from being penalized for not sending us messages.
            self.libp2p.remove_topic_weight_except(new_fork_digest);
        } else {
            crit!(new_fork_id = ?new_enr_fork_id, "Unknown new enr fork id");
        }
    }

    fn subscribed_core_topics(&self) -> bool {
        let core_topics = core_topics_to_subscribe::<T::EthSpec>(
            self.fork_context.current_fork_name(),
            &self.network_globals.as_topic_config(),
            &self.fork_context.spec,
        );
        let core_topics: HashSet<&GossipKind> = HashSet::from_iter(&core_topics);
        let subscriptions = self.network_globals.gossipsub_subscriptions.read();
        let subscribed_topics: HashSet<&GossipKind> =
            subscriptions.iter().map(|topic| topic.kind()).collect();

        core_topics.is_subset(&subscribed_topics)
    }
}

/// Returns a `Sleep` that triggers after the next change in the fork digest.
/// If there is no scheduled fork, `None` is returned.
fn next_digest_delay<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> Option<tokio::time::Sleep> {
    beacon_chain
        .duration_to_next_digest()
        .map(|(_, until_epoch)| tokio::time::sleep(until_epoch))
}

/// Returns a `Sleep` that triggers `SUBSCRIBE_DELAY_SLOTS` before the next fork digest changes.
/// Returns `None` if there are no scheduled forks or we are already past `current_slot + SUBSCRIBE_DELAY_SLOTS > fork_slot`.
fn next_topic_subscriptions_delay<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> Option<tokio::time::Sleep> {
    if let Some((_, duration_to_epoch)) = beacon_chain.duration_to_next_digest() {
        let duration_to_subscription = duration_to_epoch.saturating_sub(Duration::from_secs(
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
        debug!(number_of_peers = enrs.len(), "Persisting DHT to store");
        if let Err(e) = clear_dht::<T::EthSpec, T::HotStore, T::ColdStore>(self.store.clone()) {
            error!(error = ?e, "Failed to clear old DHT entries");
        }
        // Still try to update new entries
        match persist_dht::<T::EthSpec, T::HotStore, T::ColdStore>(self.store.clone(), enrs) {
            Err(e) => error!(
                error = ?e,
                "Failed to persist DHT on drop"
            ),
            Ok(_) => info!("Saved DHT state"),
        }
        info!("Network service shutdown");
    }
}
