use crate::behaviour::gossipsub_scoring_parameters::{
    lighthouse_gossip_thresholds, PeerScoreSettings,
};
use crate::config::gossipsub_config;
use crate::discovery::{subnet_predicate, Discovery, DiscoveryEvent, TARGET_SUBNET_PEERS};
use crate::peer_manager::{
    peerdb::score::ReportSource, ConnectionDirection, PeerManager, PeerManagerEvent,
};
use crate::rpc::*;
use crate::service::METADATA_FILENAME;
use crate::types::{
    subnet_from_topic_hash, GossipEncoding, GossipKind, GossipTopic, SnappyTransform, Subnet,
    SubnetDiscovery,
};
use crate::Eth2Enr;
use crate::{error, metrics, Enr, NetworkConfig, NetworkGlobals, PubsubMessage, TopicHash};
use futures::prelude::*;
use libp2p::{
    core::{
        connection::ConnectionId, identity::Keypair, multiaddr::Protocol as MProtocol, Multiaddr,
    },
    gossipsub::{
        subscription_filter::{MaxCountSubscriptionFilter, WhitelistSubscriptionFilter},
        Gossipsub as BaseGossipsub, GossipsubEvent, IdentTopic as Topic, MessageAcceptance,
        MessageAuthenticity, MessageId,
    },
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    swarm::{
        AddressScore, DialPeerCondition, NetworkBehaviourAction as NBAction,
        NetworkBehaviourEventProcess, PollParameters,
    },
    NetworkBehaviour, PeerId,
};
use slog::{crit, debug, o, trace, warn};
use ssz::Encode;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{
    collections::VecDeque,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};
use types::{
    consts::altair::SYNC_COMMITTEE_SUBNET_COUNT, ChainSpec, EnrForkId, EthSpec, ForkContext,
    SignedBeaconBlock, Slot, SubnetId, SyncSubnetId,
};

pub mod gossipsub_scoring_parameters;

const MAX_IDENTIFY_ADDRESSES: usize = 10;

/// Identifier of requests sent by a peer.
pub type PeerRequestId = (ConnectionId, SubstreamId);

pub type SubscriptionFilter = MaxCountSubscriptionFilter<WhitelistSubscriptionFilter>;
pub type Gossipsub = BaseGossipsub<SnappyTransform, SubscriptionFilter>;

/// The types of events than can be obtained from polling the behaviour.
#[derive(Debug)]
pub enum BehaviourEvent<TSpec: EthSpec> {
    /// We have successfully dialed and connected to a peer.
    PeerConnectedOutgoing(PeerId),
    /// A peer has successfully dialed and connected to us.
    PeerConnectedIncoming(PeerId),
    /// A peer has disconnected.
    PeerDisconnected(PeerId),
    /// The peer needs to be banned.
    PeerBanned(PeerId),
    /// The peer has been unbanned.
    PeerUnbanned(PeerId),
    /// An RPC Request that was sent failed.
    RPCFailed {
        /// The id of the failed request.
        id: RequestId,
        /// The peer to which this request was sent.
        peer_id: PeerId,
    },
    RequestReceived {
        /// The peer that sent the request.
        peer_id: PeerId,
        /// Identifier of the request. All responses to this request must use this id.
        id: PeerRequestId,
        /// Request the peer sent.
        request: Request,
    },
    ResponseReceived {
        /// Peer that sent the response.
        peer_id: PeerId,
        /// Id of the request to which the peer is responding.
        id: RequestId,
        /// Response the peer sent.
        response: Response<TSpec>,
    },
    PubsubMessage {
        /// The gossipsub message id. Used when propagating blocks after validation.
        id: MessageId,
        /// The peer from which we received this message, not the peer that published it.
        source: PeerId,
        /// The topic that this message was sent on.
        topic: TopicHash,
        /// The message itself.
        message: PubsubMessage<TSpec>,
    },
    /// Inform the network to send a Status to this peer.
    StatusPeer(PeerId),
}

/// Internal type to pass messages from sub-behaviours to the poll of the global behaviour to be
/// specified as an NBAction.
enum InternalBehaviourMessage {
    /// Dial a Peer.
    DialPeer(PeerId),
    /// The socket has been updated.
    SocketUpdated(Multiaddr),
}

/// Builds the network behaviour that manages the core protocols of eth2.
/// This core behaviour is managed by `Behaviour` which adds peer management to all core
/// behaviours.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "BehaviourEvent<TSpec>", poll_method = "poll")]
pub struct Behaviour<TSpec: EthSpec> {
    /* Sub-Behaviours */
    /// The routing pub-sub mechanism for eth2.
    gossipsub: Gossipsub,
    /// The Eth2 RPC specified in the wire-0 protocol.
    eth2_rpc: RPC<TSpec>,
    /// Discv5 Discovery protocol.
    discovery: Discovery<TSpec>,
    /// Keep regular connection to peers and disconnect if absent.
    // NOTE: The id protocol is used for initial interop. This will be removed by mainnet.
    /// Provides IP addresses and peer information.
    identify: Identify,

    /* Auxiliary Fields */
    /// The peer manager that keeps track of peer's reputation and status.
    #[behaviour(ignore)]
    peer_manager: PeerManager<TSpec>,
    /// The output events generated by this behaviour to be consumed in the swarm poll.
    #[behaviour(ignore)]
    events: VecDeque<BehaviourEvent<TSpec>>,
    /// Internal behaviour events, the NBAction type is composed of sub-behaviours, so we use a
    /// custom type here to avoid having to specify the concrete type.
    #[behaviour(ignore)]
    internal_events: VecDeque<InternalBehaviourMessage>,
    /// A collections of variables accessible outside the network service.
    #[behaviour(ignore)]
    network_globals: Arc<NetworkGlobals<TSpec>>,
    /// Keeps track of the current EnrForkId for upgrading gossipsub topics.
    // NOTE: This can be accessed via the network_globals ENR. However we keep it here for quick
    // lookups for every gossipsub message send.
    #[behaviour(ignore)]
    enr_fork_id: EnrForkId,
    /// The waker for the current task. This is used to wake the task when events are added to the
    /// queue.
    #[behaviour(ignore)]
    waker: Option<std::task::Waker>,
    /// Directory where metadata is stored.
    #[behaviour(ignore)]
    network_dir: PathBuf,
    #[behaviour(ignore)]
    fork_context: Arc<ForkContext>,
    /// Gossipsub score parameters.
    #[behaviour(ignore)]
    score_settings: PeerScoreSettings<TSpec>,
    /// The interval for updating gossipsub scores
    #[behaviour(ignore)]
    update_gossipsub_scores: tokio::time::Interval,
    /// Logger for behaviour actions.
    #[behaviour(ignore)]
    log: slog::Logger,
}

/// Implements the combined behaviour for the libp2p service.
impl<TSpec: EthSpec> Behaviour<TSpec> {
    pub async fn new(
        local_key: &Keypair,
        mut config: NetworkConfig,
        network_globals: Arc<NetworkGlobals<TSpec>>,
        log: &slog::Logger,
        fork_context: Arc<ForkContext>,
        chain_spec: &ChainSpec,
    ) -> error::Result<Self> {
        let behaviour_log = log.new(o!());

        // Set up the Identify Behaviour
        let identify_config = if config.private {
            IdentifyConfig::new(
                "".into(),
                local_key.public(), // Still send legitimate public key
            )
        } else {
            IdentifyConfig::new("eth2/1.0.0".into(), local_key.public())
                .with_agent_version(lighthouse_version::version_with_platform())
        };

        // Build and start the discovery sub-behaviour
        let mut discovery =
            Discovery::new(local_key, &config, network_globals.clone(), log).await?;
        // start searching for peers
        discovery.discover_peers();

        // Grab our local ENR FORK ID
        let enr_fork_id = network_globals
            .local_enr()
            .eth2()
            .expect("Local ENR must have a fork id");

        let possible_fork_digests = fork_context.all_fork_digests();
        let filter = MaxCountSubscriptionFilter {
            filter: Self::create_whitelist_filter(
                possible_fork_digests,
                chain_spec.attestation_subnet_count,
                SYNC_COMMITTEE_SUBNET_COUNT,
            ),
            max_subscribed_topics: 200,
            max_subscriptions_per_request: 150, // 148 in theory = (64 attestation + 4 sync committee + 6 core topics) * 2
        };

        config.gs_config = gossipsub_config(fork_context.clone());

        // Build and configure the Gossipsub behaviour
        let snappy_transform = SnappyTransform::new(config.gs_config.max_transmit_size());
        let mut gossipsub = Gossipsub::new_with_subscription_filter_and_transform(
            MessageAuthenticity::Anonymous,
            config.gs_config.clone(),
            filter,
            snappy_transform,
        )
        .map_err(|e| format!("Could not construct gossipsub: {:?}", e))?;

        // Construct a set of gossipsub peer scoring parameters
        // We don't know the number of active validators and the current slot yet
        let active_validators = TSpec::minimum_validator_count();
        let current_slot = Slot::new(0);

        let thresholds = lighthouse_gossip_thresholds();

        let score_settings = PeerScoreSettings::new(chain_spec, &config.gs_config);

        // Prepare scoring parameters
        let params = score_settings.get_peer_score_params(
            active_validators,
            &thresholds,
            &enr_fork_id,
            current_slot,
        )?;

        trace!(behaviour_log, "Using peer score params"; "params" => ?params);

        // Set up a scoring update interval
        let update_gossipsub_scores = tokio::time::interval(params.decay_interval);

        gossipsub
            .with_peer_score(params, thresholds)
            .expect("Valid score params and thresholds");

        Ok(Behaviour {
            // Sub-behaviours
            gossipsub,
            eth2_rpc: RPC::new(fork_context.clone(), log.clone()),
            discovery,
            identify: Identify::new(identify_config),
            // Auxiliary fields
            peer_manager: PeerManager::new(&config, network_globals.clone(), log).await?,
            events: VecDeque::new(),
            internal_events: VecDeque::new(),
            network_globals,
            enr_fork_id,
            waker: None,
            network_dir: config.network_dir.clone(),
            log: behaviour_log,
            score_settings,
            fork_context,
            update_gossipsub_scores,
        })
    }

    /* Public Accessible Functions to interact with the behaviour */

    /// Get a mutable reference to the underlying discovery sub-behaviour.
    pub fn discovery_mut(&mut self) -> &mut Discovery<TSpec> {
        &mut self.discovery
    }

    /// Get a mutable reference to the peer manager.
    pub fn peer_manager_mut(&mut self) -> &mut PeerManager<TSpec> {
        &mut self.peer_manager
    }

    /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> Enr {
        self.network_globals.local_enr()
    }

    /// Obtain a reference to the gossipsub protocol.
    pub fn gs(&self) -> &Gossipsub {
        &self.gossipsub
    }

    /* Pubsub behaviour functions */

    /// Subscribes to a gossipsub topic kind, letting the network service determine the
    /// encoding and fork version.
    pub fn subscribe_kind(&mut self, kind: GossipKind) -> bool {
        let gossip_topic = GossipTopic::new(
            kind,
            GossipEncoding::default(),
            self.enr_fork_id.fork_digest,
        );

        self.subscribe(gossip_topic)
    }

    /// Unsubscribes from a gossipsub topic kind, letting the network service determine the
    /// encoding and fork version.
    pub fn unsubscribe_kind(&mut self, kind: GossipKind) -> bool {
        let gossip_topic = GossipTopic::new(
            kind,
            GossipEncoding::default(),
            self.enr_fork_id.fork_digest,
        );
        self.unsubscribe(gossip_topic)
    }

    /// Subscribe to all currently subscribed topics with the new fork digest.
    pub fn subscribe_new_fork_topics(&mut self, new_fork_digest: [u8; 4]) {
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        for mut topic in subscriptions.into_iter() {
            topic.fork_digest = new_fork_digest;
            self.subscribe(topic);
        }
    }

    /// Unsubscribe from all topics that doesn't have the given fork_digest
    pub fn unsubscribe_from_fork_topics_except(&mut self, except: [u8; 4]) {
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        for topic in subscriptions
            .iter()
            .filter(|topic| topic.fork_digest != except)
            .cloned()
        {
            self.unsubscribe(topic);
        }
    }

    /// Subscribes to a gossipsub topic.
    ///
    /// Returns `true` if the subscription was successful and `false` otherwise.
    pub fn subscribe(&mut self, topic: GossipTopic) -> bool {
        // update the network globals
        self.network_globals
            .gossipsub_subscriptions
            .write()
            .insert(topic.clone());

        let topic: Topic = topic.into();

        match self.gossipsub.subscribe(&topic) {
            Err(e) => {
                warn!(self.log, "Failed to subscribe to topic"; "topic" => %topic, "error" => ?e);
                false
            }
            Ok(_) => {
                debug!(self.log, "Subscribed to topic"; "topic" => %topic);
                true
            }
        }
    }

    /// Unsubscribe from a gossipsub topic.
    pub fn unsubscribe(&mut self, topic: GossipTopic) -> bool {
        // update the network globals
        self.network_globals
            .gossipsub_subscriptions
            .write()
            .remove(&topic);

        // unsubscribe from the topic
        let topic: Topic = topic.into();

        match self.gossipsub.unsubscribe(&topic) {
            Err(_) => {
                warn!(self.log, "Failed to unsubscribe from topic"; "topic" => %topic);
                false
            }
            Ok(v) => {
                debug!(self.log, "Unsubscribed to topic"; "topic" => %topic);
                v
            }
        }
    }

    /// Publishes a list of messages on the pubsub (gossipsub) behaviour, choosing the encoding.
    pub fn publish(&mut self, messages: Vec<PubsubMessage<TSpec>>) {
        for message in messages {
            for topic in message.topics(GossipEncoding::default(), self.enr_fork_id.fork_digest) {
                let message_data = message.encode(GossipEncoding::default());
                if let Err(e) = self.gossipsub.publish(topic.clone().into(), message_data) {
                    slog::warn!(self.log, "Could not publish message";
                                        "error" => ?e);

                    // add to metrics
                    match topic.kind() {
                        GossipKind::Attestation(subnet_id) => {
                            if let Some(v) = metrics::get_int_gauge(
                                &metrics::FAILED_ATTESTATION_PUBLISHES_PER_SUBNET,
                                &[&subnet_id.to_string()],
                            ) {
                                v.inc()
                            };
                        }
                        kind => {
                            if let Some(v) = metrics::get_int_gauge(
                                &metrics::FAILED_PUBLISHES_PER_MAIN_TOPIC,
                                &[&format!("{:?}", kind)],
                            ) {
                                v.inc()
                            };
                        }
                    }
                }
            }
        }
    }

    /// Informs the gossipsub about the result of a message validation.
    /// If the message is valid it will get propagated by gossipsub.
    pub fn report_message_validation_result(
        &mut self,
        propagation_source: &PeerId,
        message_id: MessageId,
        validation_result: MessageAcceptance,
    ) {
        if let Some(result) = match validation_result {
            MessageAcceptance::Accept => None,
            MessageAcceptance::Ignore => Some("ignore"),
            MessageAcceptance::Reject => Some("reject"),
        } {
            if let Some(client) = self
                .network_globals
                .peers
                .read()
                .peer_info(propagation_source)
                .map(|info| info.client().kind.as_ref())
            {
                metrics::inc_counter_vec(
                    &metrics::GOSSIP_UNACCEPTED_MESSAGES_PER_CLIENT,
                    &[client, result],
                )
            }
        }

        if let Err(e) = self.gossipsub.report_message_validation_result(
            &message_id,
            propagation_source,
            validation_result,
        ) {
            warn!(self.log, "Failed to report message validation"; "message_id" => %message_id, "peer_id" => %propagation_source, "error" => ?e);
        }
    }

    /// Updates the current gossipsub scoring parameters based on the validator count and current
    /// slot.
    pub fn update_gossipsub_parameters(
        &mut self,
        active_validators: usize,
        current_slot: Slot,
    ) -> error::Result<()> {
        let (beacon_block_params, beacon_aggregate_proof_params, beacon_attestation_subnet_params) =
            self.score_settings
                .get_dynamic_topic_params(active_validators, current_slot)?;

        let fork_digest = self.enr_fork_id.fork_digest;
        let get_topic = |kind: GossipKind| -> Topic {
            GossipTopic::new(kind, GossipEncoding::default(), fork_digest).into()
        };

        debug!(self.log, "Updating gossipsub score parameters";
            "active_validators" => active_validators);
        trace!(self.log, "Updated gossipsub score parameters";
            "beacon_block_params" => ?beacon_block_params,
            "beacon_aggregate_proof_params" => ?beacon_aggregate_proof_params,
            "beacon_attestation_subnet_params" => ?beacon_attestation_subnet_params,
        );

        self.gossipsub
            .set_topic_params(get_topic(GossipKind::BeaconBlock), beacon_block_params)?;

        self.gossipsub.set_topic_params(
            get_topic(GossipKind::BeaconAggregateAndProof),
            beacon_aggregate_proof_params,
        )?;

        for i in 0..self.score_settings.attestation_subnet_count() {
            self.gossipsub.set_topic_params(
                get_topic(GossipKind::Attestation(SubnetId::new(i))),
                beacon_attestation_subnet_params.clone(),
            )?;
        }

        Ok(())
    }

    /* Eth2 RPC behaviour functions */

    /// Send a request to a peer over RPC.
    pub fn send_request(&mut self, peer_id: PeerId, request_id: RequestId, request: Request) {
        self.eth2_rpc
            .send_request(peer_id, request_id, request.into())
    }

    /// Send a successful response to a peer over RPC.
    pub fn send_successful_response(
        &mut self,
        peer_id: PeerId,
        id: PeerRequestId,
        response: Response<TSpec>,
    ) {
        self.eth2_rpc.send_response(peer_id, id, response.into())
    }

    /// Inform the peer that their request produced an error.
    pub fn send_error_reponse(
        &mut self,
        peer_id: PeerId,
        id: PeerRequestId,
        error: RPCResponseErrorCode,
        reason: String,
    ) {
        self.eth2_rpc
            .send_response(peer_id, id, RPCCodedResponse::Error(error, reason.into()))
    }

    /* Peer management functions */

    /// Disconnects from a peer providing a reason.
    ///
    /// This will send a goodbye, disconnect and then ban the peer.
    /// This is fatal for a peer, and should be used in unrecoverable circumstances.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        self.peer_manager.goodbye_peer(peer_id, reason, source);
    }

    /// Returns an iterator over all enr entries in the DHT.
    pub fn enr_entries(&mut self) -> Vec<Enr> {
        self.discovery.table_entries_enr()
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        self.discovery.add_enr(enr);
    }

    /// Updates a subnet value to the ENR attnets/syncnets bitfield.
    ///
    /// The `value` is `true` if a subnet is being added and false otherwise.
    pub fn update_enr_subnet(&mut self, subnet_id: Subnet, value: bool) {
        if let Err(e) = self.discovery.update_enr_bitfield(subnet_id, value) {
            crit!(self.log, "Could not update ENR bitfield"; "error" => e);
        }
        // update the local meta data which informs our peers of the update during PINGS
        self.update_metadata_bitfields();
    }

    /// Attempts to discover new peers for a given subnet. The `min_ttl` gives the time at which we
    /// would like to retain the peers for.
    pub fn discover_subnet_peers(&mut self, subnets_to_discover: Vec<SubnetDiscovery>) {
        // If discovery is not started or disabled, ignore the request
        if !self.discovery.started {
            return;
        }

        let filtered: Vec<SubnetDiscovery> = subnets_to_discover
            .into_iter()
            .filter(|s| {
                // Extend min_ttl of connected peers on required subnets
                if let Some(min_ttl) = s.min_ttl {
                    self.network_globals
                        .peers
                        .write()
                        .extend_peers_on_subnet(&s.subnet, min_ttl);
                    if let Subnet::SyncCommittee(sync_subnet) = s.subnet {
                        self.peer_manager_mut()
                            .add_sync_subnet(sync_subnet, min_ttl);
                    }
                }
                // Already have target number of peers, no need for subnet discovery
                let peers_on_subnet = self
                    .network_globals
                    .peers
                    .read()
                    .good_peers_on_subnet(s.subnet)
                    .count();
                if peers_on_subnet >= TARGET_SUBNET_PEERS {
                    trace!(
                        self.log,
                        "Discovery query ignored";
                        "subnet" => ?s.subnet,
                        "reason" => "Already connected to desired peers",
                        "connected_peers_on_subnet" => peers_on_subnet,
                        "target_subnet_peers" => TARGET_SUBNET_PEERS,
                    );
                    false
                // Queue an outgoing connection request to the cached peers that are on `s.subnet_id`.
                // If we connect to the cached peers before the discovery query starts, then we potentially
                // save a costly discovery query.
                } else {
                    self.dial_cached_enrs_in_subnet(s.subnet);
                    true
                }
            })
            .collect();

        // request the subnet query from discovery
        if !filtered.is_empty() {
            self.discovery.discover_subnet_peers(filtered);
        }
    }

    /// Updates the local ENR's "eth2" field with the latest EnrForkId.
    pub fn update_fork_version(&mut self, enr_fork_id: EnrForkId) {
        self.discovery.update_eth2_enr(enr_fork_id.clone());

        // update the local reference
        self.enr_fork_id = enr_fork_id;
    }

    /* Private internal functions */

    /// Updates the current meta data of the node to match the local ENR.
    fn update_metadata_bitfields(&mut self) {
        let local_attnets = self
            .discovery
            .local_enr()
            .attestation_bitfield::<TSpec>()
            .expect("Local discovery must have attestation bitfield");

        let local_syncnets = self
            .discovery
            .local_enr()
            .sync_committee_bitfield::<TSpec>()
            .expect("Local discovery must have sync committee bitfield");

        {
            // write lock scope
            let mut meta_data = self.network_globals.local_metadata.write();

            *meta_data.seq_number_mut() += 1;
            *meta_data.attnets_mut() = local_attnets;
            if let Ok(syncnets) = meta_data.syncnets_mut() {
                *syncnets = local_syncnets;
            }
        }
        // Save the updated metadata to disk
        save_metadata_to_disk(
            &self.network_dir,
            self.network_globals.local_metadata.read().clone(),
            &self.log,
        );
    }

    /// Sends a Ping request to the peer.
    fn ping(&mut self, id: RequestId, peer_id: PeerId) {
        let ping = crate::rpc::Ping {
            data: *self.network_globals.local_metadata.read().seq_number(),
        };
        trace!(self.log, "Sending Ping"; "request_id" => id, "peer_id" => %peer_id);

        self.eth2_rpc
            .send_request(peer_id, id, OutboundRequest::Ping(ping));
    }

    /// Sends a Pong response to the peer.
    fn pong(&mut self, id: PeerRequestId, peer_id: PeerId) {
        let ping = crate::rpc::Ping {
            data: *self.network_globals.local_metadata.read().seq_number(),
        };
        trace!(self.log, "Sending Pong"; "request_id" => id.1, "peer_id" => %peer_id);
        let event = RPCCodedResponse::Success(RPCResponse::Pong(ping));
        self.eth2_rpc.send_response(peer_id, id, event);
    }

    /// Sends a METADATA request to a peer.
    fn send_meta_data_request(&mut self, peer_id: PeerId) {
        let event = OutboundRequest::MetaData(PhantomData);
        self.eth2_rpc
            .send_request(peer_id, RequestId::Behaviour, event);
    }

    /// Sends a METADATA response to a peer.
    fn send_meta_data_response(&mut self, id: PeerRequestId, peer_id: PeerId) {
        let event = RPCCodedResponse::Success(RPCResponse::MetaData(
            self.network_globals.local_metadata.read().clone(),
        ));
        self.eth2_rpc.send_response(peer_id, id, event);
    }

    /// Returns a reference to the peer manager to allow the swarm to notify the manager of peer
    /// status
    pub fn peer_manager(&mut self) -> &mut PeerManager<TSpec> {
        &mut self.peer_manager
    }

    // RPC Propagation methods
    /// Queues the response to be sent upwards as long at it was requested outside the Behaviour.
    fn propagate_response(&mut self, id: RequestId, peer_id: PeerId, response: Response<TSpec>) {
        if !matches!(id, RequestId::Behaviour) {
            self.add_event(BehaviourEvent::ResponseReceived {
                peer_id,
                id,
                response,
            });
        }
    }

    /// Convenience function to propagate a request.
    fn propagate_request(&mut self, id: PeerRequestId, peer_id: PeerId, request: Request) {
        self.add_event(BehaviourEvent::RequestReceived {
            peer_id,
            id,
            request,
        });
    }

    /// Adds an event to the queue waking the current task to process it.
    fn add_event(&mut self, event: BehaviourEvent<TSpec>) {
        self.events.push_back(event);
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }

    /// Dial cached enrs in discovery service that are in the given `subnet_id` and aren't
    /// in Connected, Dialing or Banned state.
    fn dial_cached_enrs_in_subnet(&mut self, subnet: Subnet) {
        let predicate = subnet_predicate::<TSpec>(vec![subnet], &self.log);
        let peers_to_dial: Vec<PeerId> = self
            .discovery
            .cached_enrs()
            .filter_map(|(peer_id, enr)| {
                let peers = self.network_globals.peers.read();
                if predicate(enr) && peers.should_dial(peer_id) {
                    Some(*peer_id)
                } else {
                    None
                }
            })
            .collect();
        for peer_id in peers_to_dial {
            debug!(self.log, "Dialing cached ENR peer"; "peer_id" => %peer_id);
            // Remove the ENR from the cache to prevent continual re-dialing on disconnects
            self.discovery.remove_cached_enr(&peer_id);
            self.internal_events
                .push_back(InternalBehaviourMessage::DialPeer(peer_id));
        }
    }

    /// Creates a whitelist topic filter that covers all possible topics using the given set of
    /// possible fork digests.
    fn create_whitelist_filter(
        possible_fork_digests: Vec<[u8; 4]>,
        attestation_subnet_count: u64,
        sync_committee_subnet_count: u64,
    ) -> WhitelistSubscriptionFilter {
        let mut possible_hashes = HashSet::new();
        for fork_digest in possible_fork_digests {
            let mut add = |kind| {
                let topic: Topic =
                    GossipTopic::new(kind, GossipEncoding::SSZSnappy, fork_digest).into();
                possible_hashes.insert(topic.hash());
            };

            use GossipKind::*;
            add(BeaconBlock);
            add(BeaconAggregateAndProof);
            add(VoluntaryExit);
            add(ProposerSlashing);
            add(AttesterSlashing);
            add(SignedContributionAndProof);
            for id in 0..attestation_subnet_count {
                add(Attestation(SubnetId::new(id)));
            }
            for id in 0..sync_committee_subnet_count {
                add(SyncCommitteeMessage(SyncSubnetId::new(id)));
            }
        }
        WhitelistSubscriptionFilter(possible_hashes)
    }
}

/* Behaviour Event Process Implementations
 *
 * These implementations dictate how to process each event that is emitted from each
 * sub-behaviour.
 */

// Gossipsub
impl<TSpec: EthSpec> NetworkBehaviourEventProcess<GossipsubEvent> for Behaviour<TSpec> {
    fn inject_event(&mut self, event: GossipsubEvent) {
        match event {
            GossipsubEvent::Message {
                propagation_source,
                message_id: id,
                message: gs_msg,
            } => {
                // Note: We are keeping track here of the peer that sent us the message, not the
                // peer that originally published the message.
                match PubsubMessage::decode(&gs_msg.topic, &gs_msg.data, &self.fork_context) {
                    Err(e) => {
                        debug!(self.log, "Could not decode gossipsub message"; "topic" => ?gs_msg.topic,"error" => e);
                        //reject the message
                        if let Err(e) = self.gossipsub.report_message_validation_result(
                            &id,
                            &propagation_source,
                            MessageAcceptance::Reject,
                        ) {
                            warn!(self.log, "Failed to report message validation"; "message_id" => %id, "peer_id" => %propagation_source, "error" => ?e);
                        }
                    }
                    Ok(msg) => {
                        // Notify the network
                        self.add_event(BehaviourEvent::PubsubMessage {
                            id,
                            source: propagation_source,
                            topic: gs_msg.topic,
                            message: msg,
                        });
                    }
                }
            }
            GossipsubEvent::Subscribed { peer_id, topic } => {
                if let Some(subnet_id) = subnet_from_topic_hash(&topic) {
                    self.network_globals
                        .peers
                        .write()
                        .add_subscription(&peer_id, subnet_id);
                }
            }
            GossipsubEvent::Unsubscribed { peer_id, topic } => {
                if let Some(subnet_id) = subnet_from_topic_hash(&topic) {
                    self.network_globals
                        .peers
                        .write()
                        .remove_subscription(&peer_id, &subnet_id);
                }
            }
        }
    }
}

// RPC
impl<TSpec: EthSpec> NetworkBehaviourEventProcess<RPCMessage<TSpec>> for Behaviour<TSpec> {
    fn inject_event(&mut self, event: RPCMessage<TSpec>) {
        let peer_id = event.peer_id;

        if !self.peer_manager.is_connected(&peer_id) {
            debug!(
                self.log,
                "Ignoring rpc message of disconnecting peer";
                "peer" => %peer_id
            );
            return;
        }

        let handler_id = event.conn_id;
        // The METADATA and PING RPC responses are handled within the behaviour and not propagated
        match event.event {
            Err(handler_err) => {
                match handler_err {
                    HandlerErr::Inbound {
                        id: _,
                        proto,
                        error,
                    } => {
                        if matches!(error, RPCError::HandlerRejected) {
                            // this peer's request got canceled
                        }
                        // Inform the peer manager of the error.
                        // An inbound error here means we sent an error to the peer, or the stream
                        // timed out.
                        self.peer_manager.handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Incoming,
                        );
                    }
                    HandlerErr::Outbound { id, proto, error } => {
                        // Inform the peer manager that a request we sent to the peer failed
                        self.peer_manager.handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Outgoing,
                        );
                        // inform failures of requests comming outside the behaviour
                        if !matches!(id, RequestId::Behaviour) {
                            self.add_event(BehaviourEvent::RPCFailed { peer_id, id });
                        }
                    }
                }
            }
            Ok(RPCReceived::Request(id, request)) => {
                let peer_request_id = (handler_id, id);
                match request {
                    /* Behaviour managed protocols: Ping and Metadata */
                    InboundRequest::Ping(ping) => {
                        // inform the peer manager and send the response
                        self.peer_manager.ping_request(&peer_id, ping.data);
                        // send a ping response
                        self.pong(peer_request_id, peer_id);
                    }
                    InboundRequest::MetaData(_) => {
                        // send the requested meta-data
                        self.send_meta_data_response((handler_id, id), peer_id);
                    }
                    InboundRequest::Goodbye(reason) => {
                        // queue for disconnection without a goodbye message
                        debug!(
                            self.log, "Peer sent Goodbye";
                            "peer_id" => %peer_id,
                            "reason" => %reason,
                            "client" => %self.network_globals.client(&peer_id),
                        );
                        // NOTE: We currently do not inform the application that we are
                        // disconnecting here. The RPC handler will automatically
                        // disconnect for us.
                        // The actual disconnection event will be relayed to the application.
                    }
                    /* Protocols propagated to the Network */
                    InboundRequest::Status(msg) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager.peer_statusd(&peer_id);
                        // propagate the STATUS message upwards
                        self.propagate_request(peer_request_id, peer_id, Request::Status(msg))
                    }
                    InboundRequest::BlocksByRange(req) => self.propagate_request(
                        peer_request_id,
                        peer_id,
                        Request::BlocksByRange(req),
                    ),
                    InboundRequest::BlocksByRoot(req) => {
                        self.propagate_request(peer_request_id, peer_id, Request::BlocksByRoot(req))
                    }
                }
            }
            Ok(RPCReceived::Response(id, resp)) => {
                match resp {
                    /* Behaviour managed protocols */
                    RPCResponse::Pong(ping) => self.peer_manager.pong_response(&peer_id, ping.data),
                    RPCResponse::MetaData(meta_data) => {
                        self.peer_manager.meta_data_response(&peer_id, meta_data)
                    }
                    /* Network propagated protocols */
                    RPCResponse::Status(msg) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager.peer_statusd(&peer_id);
                        // propagate the STATUS message upwards
                        self.propagate_response(id, peer_id, Response::Status(msg));
                    }
                    RPCResponse::BlocksByRange(resp) => {
                        self.propagate_response(id, peer_id, Response::BlocksByRange(Some(resp)))
                    }
                    RPCResponse::BlocksByRoot(resp) => {
                        self.propagate_response(id, peer_id, Response::BlocksByRoot(Some(resp)))
                    }
                }
            }
            Ok(RPCReceived::EndOfStream(id, termination)) => {
                let response = match termination {
                    ResponseTermination::BlocksByRange => Response::BlocksByRange(None),
                    ResponseTermination::BlocksByRoot => Response::BlocksByRoot(None),
                };
                self.propagate_response(id, peer_id, response);
            }
        }
    }
}

// Discovery
impl<TSpec: EthSpec> NetworkBehaviourEventProcess<DiscoveryEvent> for Behaviour<TSpec> {
    fn inject_event(&mut self, event: DiscoveryEvent) {
        match event {
            DiscoveryEvent::SocketUpdated(socket_addr) => {
                // A new UDP socket has been detected.
                // Build a multiaddr to report to libp2p
                let mut multiaddr = Multiaddr::from(socket_addr.ip());
                // NOTE: This doesn't actually track the external TCP port. More sophisticated NAT handling
                // should handle this.
                multiaddr.push(MProtocol::Tcp(self.network_globals.listen_port_tcp()));
                self.internal_events
                    .push_back(InternalBehaviourMessage::SocketUpdated(multiaddr));
            }
            DiscoveryEvent::QueryResult(results) => {
                let to_dial_peers = self.peer_manager.peers_discovered(results);
                for peer_id in to_dial_peers {
                    debug!(self.log, "Dialing discovered peer"; "peer_id" => %peer_id);
                    self.internal_events
                        .push_back(InternalBehaviourMessage::DialPeer(peer_id));
                }
            }
        }
    }
}

// Identify
impl<TSpec: EthSpec> NetworkBehaviourEventProcess<IdentifyEvent> for Behaviour<TSpec> {
    fn inject_event(&mut self, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Received { peer_id, mut info } => {
                if info.listen_addrs.len() > MAX_IDENTIFY_ADDRESSES {
                    debug!(
                        self.log,
                        "More than 10 addresses have been identified, truncating"
                    );
                    info.listen_addrs.truncate(MAX_IDENTIFY_ADDRESSES);
                }
                // send peer info to the peer manager.
                self.peer_manager.identify(&peer_id, &info);
            }
            IdentifyEvent::Sent { .. } => {}
            IdentifyEvent::Error { .. } => {}
            IdentifyEvent::Pushed { .. } => {}
        }
    }
}

impl<TSpec: EthSpec> Behaviour<TSpec> {
    /// Consumes the events list and drives the Lighthouse global NetworkBehaviour.
    fn poll<THandlerIn>(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NBAction<THandlerIn, BehaviourEvent<TSpec>>> {
        if let Some(waker) = &self.waker {
            if waker.will_wake(cx.waker()) {
                self.waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(cx.waker().clone());
        }

        // Handle internal events first
        if let Some(event) = self.internal_events.pop_front() {
            match event {
                InternalBehaviourMessage::DialPeer(peer_id) => {
                    return Poll::Ready(NBAction::DialPeer {
                        peer_id,
                        condition: DialPeerCondition::Disconnected,
                    });
                }
                InternalBehaviourMessage::SocketUpdated(address) => {
                    return Poll::Ready(NBAction::ReportObservedAddr {
                        address,
                        score: AddressScore::Finite(1),
                    });
                }
            }
        }

        // check the peer manager for events
        loop {
            match self.peer_manager.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => match event {
                    PeerManagerEvent::PeerConnectedIncoming(peer_id) => {
                        return Poll::Ready(NBAction::GenerateEvent(
                            BehaviourEvent::PeerConnectedIncoming(peer_id),
                        ));
                    }
                    PeerManagerEvent::PeerConnectedOutgoing(peer_id) => {
                        return Poll::Ready(NBAction::GenerateEvent(
                            BehaviourEvent::PeerConnectedOutgoing(peer_id),
                        ));
                    }
                    PeerManagerEvent::PeerDisconnected(peer_id) => {
                        return Poll::Ready(NBAction::GenerateEvent(
                            BehaviourEvent::PeerDisconnected(peer_id),
                        ));
                    }
                    PeerManagerEvent::Banned(peer_id, associated_ips) => {
                        self.discovery.ban_peer(&peer_id, associated_ips);
                        return Poll::Ready(NBAction::GenerateEvent(BehaviourEvent::PeerBanned(
                            peer_id,
                        )));
                    }
                    PeerManagerEvent::UnBanned(peer_id, associated_ips) => {
                        self.discovery.unban_peer(&peer_id, associated_ips);
                        return Poll::Ready(NBAction::GenerateEvent(BehaviourEvent::PeerUnbanned(
                            peer_id,
                        )));
                    }
                    PeerManagerEvent::Status(peer_id) => {
                        // it's time to status. We don't keep a beacon chain reference here, so we inform
                        // the network to send a status to this peer
                        return Poll::Ready(NBAction::GenerateEvent(BehaviourEvent::StatusPeer(
                            peer_id,
                        )));
                    }
                    PeerManagerEvent::DiscoverPeers => {
                        // Peer manager has requested a discovery query for more peers.
                        self.discovery.discover_peers();
                    }
                    PeerManagerEvent::DiscoverSubnetPeers(subnets_to_discover) => {
                        // Peer manager has requested a subnet discovery query for more peers.
                        self.discover_subnet_peers(subnets_to_discover);
                    }
                    PeerManagerEvent::Ping(peer_id) => {
                        // send a ping request to this peer
                        self.ping(RequestId::Behaviour, peer_id);
                    }
                    PeerManagerEvent::MetaData(peer_id) => {
                        self.send_meta_data_request(peer_id);
                    }
                    PeerManagerEvent::DisconnectPeer(peer_id, reason) => {
                        debug!(self.log, "Peer Manager disconnecting peer";
                            "peer_id" => %peer_id, "reason" => %reason);
                        // send one goodbye
                        self.eth2_rpc.shutdown(peer_id, reason);
                    }
                },
                Poll::Pending => break,
                Poll::Ready(None) => break, // peer manager ended
            }
        }

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(NBAction::GenerateEvent(event));
        }

        // perform gossipsub score updates when necessary
        while self.update_gossipsub_scores.poll_tick(cx).is_ready() {
            self.peer_manager.update_gossipsub_scores(&self.gossipsub);
        }

        Poll::Pending
    }
}

/* Public API types */

/// The type of RPC requests the Behaviour informs it has received and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level requests that can be
//       sent. The main difference is the absence of the Ping, Metadata and Goodbye protocols, which don't
//       leave the Behaviour. For all protocols managed by RPC see `RPCRequest`.
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    /// A Status message.
    Status(StatusMessage),
    /// A blocks by range request.
    BlocksByRange(BlocksByRangeRequest),
    /// A request blocks root request.
    BlocksByRoot(BlocksByRootRequest),
}

impl<TSpec: EthSpec> std::convert::From<Request> for OutboundRequest<TSpec> {
    fn from(req: Request) -> OutboundRequest<TSpec> {
        match req {
            Request::BlocksByRoot(r) => OutboundRequest::BlocksByRoot(r),
            Request::BlocksByRange(r) => OutboundRequest::BlocksByRange(r),
            Request::Status(s) => OutboundRequest::Status(s),
        }
    }
}

/// The type of RPC responses the Behaviour informs it has received, and allows for sending.
///
// NOTE: This is an application-level wrapper over the lower network level responses that can be
//       sent. The main difference is the absense of Pong and Metadata, which don't leave the
//       Behaviour. For all protocol reponses managed by RPC see `RPCResponse` and
//       `RPCCodedResponse`.
#[derive(Debug, Clone, PartialEq)]
pub enum Response<TSpec: EthSpec> {
    /// A Status message.
    Status(StatusMessage),
    /// A response to a get BLOCKS_BY_RANGE request. A None response signals the end of the batch.
    BlocksByRange(Option<Box<SignedBeaconBlock<TSpec>>>),
    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Option<Box<SignedBeaconBlock<TSpec>>>),
}

impl<TSpec: EthSpec> std::convert::From<Response<TSpec>> for RPCCodedResponse<TSpec> {
    fn from(resp: Response<TSpec>) -> RPCCodedResponse<TSpec> {
        match resp {
            Response::BlocksByRoot(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::BlocksByRoot(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::BlocksByRoot),
            },
            Response::BlocksByRange(r) => match r {
                Some(b) => RPCCodedResponse::Success(RPCResponse::BlocksByRange(b)),
                None => RPCCodedResponse::StreamTermination(ResponseTermination::BlocksByRange),
            },
            Response::Status(s) => RPCCodedResponse::Success(RPCResponse::Status(s)),
        }
    }
}

/// Persist metadata to disk
pub fn save_metadata_to_disk<E: EthSpec>(dir: &Path, metadata: MetaData<E>, log: &slog::Logger) {
    let _ = std::fs::create_dir_all(&dir);
    match File::create(dir.join(METADATA_FILENAME))
        .and_then(|mut f| f.write_all(&metadata.as_ssz_bytes()))
    {
        Ok(_) => {
            debug!(log, "Metadata written to disk");
        }
        Err(e) => {
            warn!(
                log,
                "Could not write metadata to disk";
                "file" => format!("{:?}{:?}", dir, METADATA_FILENAME),
                "error" => %e
            );
        }
    }
}
