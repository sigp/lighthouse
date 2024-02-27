use self::behaviour::Behaviour;
use self::gossip_cache::GossipCache;
use crate::config::{gossipsub_config, GossipsubConfigParams, NetworkLoad};
use crate::discovery::{
    subnet_predicate, DiscoveredPeers, Discovery, FIND_NODE_QUERY_CLOSEST_PEERS,
};
use crate::gossipsub::{
    self, IdentTopic as Topic, MessageAcceptance, MessageAuthenticity, MessageId, PublishError,
    TopicScoreParams,
};
use crate::peer_manager::{
    config::Config as PeerManagerCfg, peerdb::score::PeerAction, peerdb::score::ReportSource,
    ConnectionDirection, PeerManager, PeerManagerEvent,
};
use crate::peer_manager::{MIN_OUTBOUND_ONLY_FACTOR, PEER_EXCESS_FACTOR, PRIORITY_PEER_EXCESS};
use crate::rpc::methods::MetadataRequest;
use crate::rpc::*;
use crate::service::behaviour::BehaviourEvent;
pub use crate::service::behaviour::Gossipsub;
use crate::types::{
    fork_core_topics, subnet_from_topic_hash, GossipEncoding, GossipKind, GossipTopic,
    SnappyTransform, Subnet, SubnetDiscovery, ALTAIR_CORE_TOPICS, BASE_CORE_TOPICS,
    CAPELLA_CORE_TOPICS, DENEB_CORE_TOPICS, LIGHT_CLIENT_GOSSIP_TOPICS,
};
use crate::EnrExt;
use crate::Eth2Enr;
use crate::{error, metrics, Enr, NetworkGlobals, PubsubMessage, TopicHash};
use api_types::{PeerRequestId, Request, RequestId, Response};
use futures::stream::StreamExt;
use gossipsub_scoring_parameters::{lighthouse_gossip_thresholds, PeerScoreSettings};
use libp2p::multiaddr::{self, Multiaddr, Protocol as MProtocol};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{identify, PeerId, SwarmBuilder};
use slog::{crit, debug, info, o, trace, warn};
use std::path::PathBuf;
use std::pin::Pin;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use types::ForkName;
use types::{
    consts::altair::SYNC_COMMITTEE_SUBNET_COUNT, EnrForkId, EthSpec, ForkContext, Slot, SubnetId,
};
use utils::{build_transport, strip_peer_id, Context as ServiceContext, MAX_CONNECTIONS_PER_PEER};

pub mod api_types;
mod behaviour;
mod gossip_cache;
pub mod gossipsub_scoring_parameters;
pub mod utils;
/// The number of peers we target per subnet for discovery queries.
pub const TARGET_SUBNET_PEERS: usize = 3;

const MAX_IDENTIFY_ADDRESSES: usize = 10;

/// The types of events than can be obtained from polling the behaviour.
#[derive(Debug)]
pub enum NetworkEvent<AppReqId: ReqId, TSpec: EthSpec> {
    /// We have successfully dialed and connected to a peer.
    PeerConnectedOutgoing(PeerId),
    /// A peer has successfully dialed and connected to us.
    PeerConnectedIncoming(PeerId),
    /// A peer has disconnected.
    PeerDisconnected(PeerId),
    /// An RPC Request that was sent failed.
    RPCFailed {
        /// The id of the failed request.
        id: AppReqId,
        /// The peer to which this request was sent.
        peer_id: PeerId,
        /// The error of the failed request.
        error: RPCError,
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
        id: AppReqId,
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
    NewListenAddr(Multiaddr),
    ZeroListeners,
}

/// Builds the network behaviour that manages the core protocols of eth2.
/// This core behaviour is managed by `Behaviour` which adds peer management to all core
/// behaviours.
pub struct Network<AppReqId: ReqId, TSpec: EthSpec> {
    swarm: libp2p::swarm::Swarm<Behaviour<AppReqId, TSpec>>,
    /* Auxiliary Fields */
    /// A collections of variables accessible outside the network service.
    network_globals: Arc<NetworkGlobals<TSpec>>,
    /// Keeps track of the current EnrForkId for upgrading gossipsub topics.
    // NOTE: This can be accessed via the network_globals ENR. However we keep it here for quick
    // lookups for every gossipsub message send.
    enr_fork_id: EnrForkId,
    /// Directory where metadata is stored.
    network_dir: PathBuf,
    fork_context: Arc<ForkContext>,
    /// Gossipsub score parameters.
    score_settings: PeerScoreSettings<TSpec>,
    /// The interval for updating gossipsub scores
    update_gossipsub_scores: tokio::time::Interval,
    gossip_cache: GossipCache,
    /// This node's PeerId.
    pub local_peer_id: PeerId,
    /// Logger for behaviour actions.
    log: slog::Logger,
}

/// Implements the combined behaviour for the libp2p service.
impl<AppReqId: ReqId, TSpec: EthSpec> Network<AppReqId, TSpec> {
    pub async fn new(
        executor: task_executor::TaskExecutor,
        mut ctx: ServiceContext<'_>,
        log: &slog::Logger,
    ) -> error::Result<(Self, Arc<NetworkGlobals<TSpec>>)> {
        let log = log.new(o!("service"=> "libp2p"));

        let mut config = ctx.config.clone();
        trace!(log, "Libp2p Service starting");
        // initialise the node's ID
        let local_keypair = utils::load_private_key(&config, &log);

        // set up a collection of variables accessible outside of the network crate
        let network_globals = {
            // Create an ENR or load from disk if appropriate
            let enr = crate::discovery::enr::build_or_load_enr::<TSpec>(
                local_keypair.clone(),
                &config,
                &ctx.enr_fork_id,
                &log,
            )?;
            // Construct the metadata
            let meta_data = utils::load_or_build_metadata(&config.network_dir, &log);
            let globals = NetworkGlobals::new(
                enr,
                meta_data,
                config
                    .trusted_peers
                    .iter()
                    .map(|x| PeerId::from(x.clone()))
                    .collect(),
                config.disable_peer_scoring,
                &log,
            );
            Arc::new(globals)
        };

        // Grab our local ENR FORK ID
        let enr_fork_id = network_globals
            .local_enr()
            .eth2()
            .expect("Local ENR must have a fork id");

        let score_settings = PeerScoreSettings::new(ctx.chain_spec, &config.gs_config);

        let gossip_cache = {
            let slot_duration = std::time::Duration::from_secs(ctx.chain_spec.seconds_per_slot);
            let half_epoch = std::time::Duration::from_secs(
                ctx.chain_spec.seconds_per_slot * TSpec::slots_per_epoch() / 2,
            );

            GossipCache::builder()
                .beacon_block_timeout(slot_duration)
                .aggregates_timeout(half_epoch)
                .attestation_timeout(half_epoch)
                .voluntary_exit_timeout(half_epoch * 2)
                .proposer_slashing_timeout(half_epoch * 2)
                .attester_slashing_timeout(half_epoch * 2)
                // .signed_contribution_and_proof_timeout(timeout) // Do not retry
                // .sync_committee_message_timeout(timeout) // Do not retry
                .bls_to_execution_change_timeout(half_epoch * 2)
                .build()
        };

        let local_peer_id = network_globals.local_peer_id();

        let (gossipsub, update_gossipsub_scores) = {
            let thresholds = lighthouse_gossip_thresholds();

            // Prepare scoring parameters
            let params = {
                // Construct a set of gossipsub peer scoring parameters
                // We don't know the number of active validators and the current slot yet
                let active_validators = TSpec::minimum_validator_count();
                let current_slot = Slot::new(0);
                score_settings.get_peer_score_params(
                    active_validators,
                    &thresholds,
                    &enr_fork_id,
                    current_slot,
                )?
            };

            trace!(log, "Using peer score params"; "params" => ?params);

            // Set up a scoring update interval
            let update_gossipsub_scores = tokio::time::interval(params.decay_interval);

            let max_topics = ctx.chain_spec.attestation_subnet_count as usize
                + SYNC_COMMITTEE_SUBNET_COUNT as usize
                + ctx.chain_spec.blob_sidecar_subnet_count as usize
                + BASE_CORE_TOPICS.len()
                + ALTAIR_CORE_TOPICS.len()
                + CAPELLA_CORE_TOPICS.len()
                + DENEB_CORE_TOPICS.len()
                + LIGHT_CLIENT_GOSSIP_TOPICS.len();

            let possible_fork_digests = ctx.fork_context.all_fork_digests();
            let filter = gossipsub::MaxCountSubscriptionFilter {
                filter: utils::create_whitelist_filter(
                    possible_fork_digests,
                    ctx.chain_spec.attestation_subnet_count,
                    SYNC_COMMITTEE_SUBNET_COUNT,
                    ctx.chain_spec.blob_sidecar_subnet_count,
                ),
                // during a fork we subscribe to both the old and new topics
                max_subscribed_topics: max_topics * 4,
                // 162 in theory = (64 attestation + 4 sync committee + 7 core topics + 6 blob topics) * 2
                max_subscriptions_per_request: max_topics * 2,
            };

            let gossipsub_config_params = GossipsubConfigParams {
                message_domain_valid_snappy: ctx.chain_spec.message_domain_valid_snappy,
                gossip_max_size: ctx.chain_spec.gossip_max_size as usize,
            };
            config.gs_config = gossipsub_config(
                config.network_load,
                ctx.fork_context.clone(),
                gossipsub_config_params,
            );

            // If metrics are enabled for libp2p build the configuration
            let gossipsub_metrics = ctx.libp2p_registry.as_mut().map(|registry| {
                (
                    registry.sub_registry_with_prefix("gossipsub"),
                    Default::default(),
                )
            });

            let snappy_transform = SnappyTransform::new(config.gs_config.max_transmit_size());
            let mut gossipsub = Gossipsub::new_with_subscription_filter_and_transform(
                MessageAuthenticity::Anonymous,
                config.gs_config.clone(),
                gossipsub_metrics,
                filter,
                snappy_transform,
            )
            .map_err(|e| format!("Could not construct gossipsub: {:?}", e))?;

            gossipsub
                .with_peer_score(params, thresholds)
                .expect("Valid score params and thresholds");

            (gossipsub, update_gossipsub_scores)
        };

        let network_params = NetworkParams {
            max_chunk_size: ctx.chain_spec.max_chunk_size as usize,
            ttfb_timeout: ctx.chain_spec.ttfb_timeout(),
            resp_timeout: ctx.chain_spec.resp_timeout(),
        };
        let eth2_rpc = RPC::new(
            ctx.fork_context.clone(),
            config.enable_light_client_server,
            config.inbound_rate_limiter_config.clone(),
            config.outbound_rate_limiter_config.clone(),
            log.clone(),
            network_params,
        );

        let discovery = {
            // Build and start the discovery sub-behaviour
            let mut discovery = Discovery::new(
                local_keypair.clone(),
                &config,
                network_globals.clone(),
                &log,
            )
            .await?;
            // start searching for peers
            discovery.discover_peers(FIND_NODE_QUERY_CLOSEST_PEERS);
            discovery
        };

        let identify = {
            let local_public_key = local_keypair.public();
            let identify_config = if config.private {
                identify::Config::new(
                    "".into(),
                    local_public_key, // Still send legitimate public key
                )
                .with_cache_size(0)
            } else {
                identify::Config::new("eth2/1.0.0".into(), local_public_key)
                    .with_agent_version(lighthouse_version::version_with_platform())
                    .with_cache_size(0)
            };
            identify::Behaviour::new(identify_config)
        };

        let peer_manager = {
            let peer_manager_cfg = PeerManagerCfg {
                discovery_enabled: !config.disable_discovery,
                quic_enabled: !config.disable_quic_support,
                metrics_enabled: config.metrics_enabled,
                target_peer_count: config.target_peers,
                ..Default::default()
            };
            PeerManager::new(peer_manager_cfg, network_globals.clone(), &log)?
        };

        let connection_limits = {
            let limits = libp2p::connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(5))
                .with_max_pending_outgoing(Some(16))
                .with_max_established_incoming(Some(
                    (config.target_peers as f32
                        * (1.0 + PEER_EXCESS_FACTOR - MIN_OUTBOUND_ONLY_FACTOR))
                        .ceil() as u32,
                ))
                .with_max_established_outgoing(Some(
                    (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as u32,
                ))
                .with_max_established(Some(
                    (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS))
                        .ceil() as u32,
                ))
                .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER));

            libp2p::connection_limits::Behaviour::new(limits)
        };

        let behaviour = {
            Behaviour {
                gossipsub,
                eth2_rpc,
                discovery,
                identify,
                peer_manager,
                connection_limits,
                upnp: Default::default(),
            }
        };

        // Set up the transport - tcp/quic with noise and mplex
        let transport = build_transport(local_keypair.clone(), !config.disable_quic_support)
            .map_err(|e| format!("Failed to build transport: {:?}", e))?;

        // use the executor for libp2p
        struct Executor(task_executor::TaskExecutor);
        impl libp2p::swarm::Executor for Executor {
            fn exec(&self, f: Pin<Box<dyn futures::Future<Output = ()> + Send>>) {
                self.0.spawn(f, "libp2p");
            }
        }

        // sets up the libp2p swarm.

        let swarm = {
            let builder = SwarmBuilder::with_existing_identity(local_keypair)
                .with_tokio()
                .with_other_transport(|_key| transport)
                .expect("infalible");

            // NOTE: adding bandwidth metrics changes the generics of the swarm, so types diverge
            if let Some(libp2p_registry) = ctx.libp2p_registry {
                builder
                    .with_bandwidth_metrics(libp2p_registry)
                    .with_behaviour(|_| behaviour)
                    .expect("infalible")
                    .with_swarm_config(|_| {
                        libp2p::swarm::Config::with_executor(Executor(executor))
                            .with_notify_handler_buffer_size(
                                std::num::NonZeroUsize::new(7).expect("Not zero"),
                            )
                            .with_per_connection_event_buffer_size(4)
                    })
                    .build()
            } else {
                builder
                    .with_behaviour(|_| behaviour)
                    .expect("infalible")
                    .with_swarm_config(|_| {
                        libp2p::swarm::Config::with_executor(Executor(executor))
                            .with_notify_handler_buffer_size(
                                std::num::NonZeroUsize::new(7).expect("Not zero"),
                            )
                            .with_per_connection_event_buffer_size(4)
                    })
                    .build()
            }
        };

        let mut network = Network {
            swarm,
            network_globals,
            enr_fork_id,
            network_dir: config.network_dir.clone(),
            fork_context: ctx.fork_context,
            score_settings,
            update_gossipsub_scores,
            gossip_cache,
            local_peer_id,
            log,
        };

        network.start(&config).await?;

        let network_globals = network.network_globals.clone();

        Ok((network, network_globals))
    }

    /// Starts the network:
    ///
    /// - Starts listening in the given ports.
    /// - Dials boot-nodes and libp2p peers.
    /// - Subscribes to starting gossipsub topics.
    async fn start(&mut self, config: &crate::NetworkConfig) -> error::Result<()> {
        let enr = self.network_globals.local_enr();
        info!(self.log, "Libp2p Starting"; "peer_id" => %enr.peer_id(), "bandwidth_config" => format!("{}-{}", config.network_load, NetworkLoad::from(config.network_load).name));
        debug!(self.log, "Attempting to open listening ports"; config.listen_addrs(), "discovery_enabled" => !config.disable_discovery, "quic_enabled" => !config.disable_quic_support);

        for listen_multiaddr in config.listen_addrs().libp2p_addresses() {
            // If QUIC is disabled, ignore listening on QUIC ports
            if config.disable_quic_support
                && listen_multiaddr.iter().any(|v| v == MProtocol::QuicV1)
            {
                continue;
            }

            match self.swarm.listen_on(listen_multiaddr.clone()) {
                Ok(_) => {
                    let mut log_address = listen_multiaddr;
                    log_address.push(MProtocol::P2p(enr.peer_id()));
                    info!(self.log, "Listening established"; "address" => %log_address);
                }
                Err(err) => {
                    crit!(
                        self.log,
                        "Unable to listen on libp2p address";
                        "error" => ?err,
                        "listen_multiaddr" => %listen_multiaddr,
                    );
                    return Err("Libp2p was unable to listen on the given listen address.".into());
                }
            };
        }

        // helper closure for dialing peers
        let mut dial = |mut multiaddr: Multiaddr| {
            // strip the p2p protocol if it exists
            strip_peer_id(&mut multiaddr);
            match self.swarm.dial(multiaddr.clone()) {
                Ok(()) => debug!(self.log, "Dialing libp2p peer"; "address" => %multiaddr),
                Err(err) => {
                    debug!(self.log, "Could not connect to peer"; "address" => %multiaddr, "error" => ?err)
                }
            };
        };

        // attempt to connect to user-input libp2p nodes
        for multiaddr in &config.libp2p_nodes {
            dial(multiaddr.clone());
        }

        // attempt to connect to any specified boot-nodes
        let mut boot_nodes = config.boot_nodes_enr.clone();
        boot_nodes.dedup();

        for bootnode_enr in boot_nodes {
            // If QUIC is enabled, attempt QUIC connections first
            if !config.disable_quic_support {
                for quic_multiaddr in &bootnode_enr.multiaddr_quic() {
                    if !self
                        .network_globals
                        .peers
                        .read()
                        .is_connected_or_dialing(&bootnode_enr.peer_id())
                    {
                        dial(quic_multiaddr.clone());
                    }
                }
            }

            for multiaddr in &bootnode_enr.multiaddr() {
                // ignore udp multiaddr if it exists
                let components = multiaddr.iter().collect::<Vec<_>>();
                if let MProtocol::Udp(_) = components[1] {
                    continue;
                }

                if !self
                    .network_globals
                    .peers
                    .read()
                    .is_connected_or_dialing(&bootnode_enr.peer_id())
                {
                    dial(multiaddr.clone());
                }
            }
        }

        for multiaddr in &config.boot_nodes_multiaddr {
            // check TCP support for dialing
            if multiaddr
                .iter()
                .any(|proto| matches!(proto, MProtocol::Tcp(_)))
            {
                dial(multiaddr.clone());
            }
        }

        let mut subscribed_topics: Vec<GossipKind> = vec![];

        for topic_kind in &config.topics {
            if self.subscribe_kind(topic_kind.clone()) {
                subscribed_topics.push(topic_kind.clone());
            } else {
                warn!(self.log, "Could not subscribe to topic"; "topic" => %topic_kind);
            }
        }

        if !subscribed_topics.is_empty() {
            info!(self.log, "Subscribed to topics"; "topics" => ?subscribed_topics);
        }

        Ok(())
    }

    /* Public Accessible Functions to interact with the behaviour */

    /// The routing pub-sub mechanism for eth2.
    pub fn gossipsub_mut(&mut self) -> &mut Gossipsub {
        &mut self.swarm.behaviour_mut().gossipsub
    }
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub fn eth2_rpc_mut(&mut self) -> &mut RPC<RequestId<AppReqId>, TSpec> {
        &mut self.swarm.behaviour_mut().eth2_rpc
    }
    /// Discv5 Discovery protocol.
    pub fn discovery_mut(&mut self) -> &mut Discovery<TSpec> {
        &mut self.swarm.behaviour_mut().discovery
    }
    /// Provides IP addresses and peer information.
    pub fn identify_mut(&mut self) -> &mut identify::Behaviour {
        &mut self.swarm.behaviour_mut().identify
    }
    /// The peer manager that keeps track of peer's reputation and status.
    pub fn peer_manager_mut(&mut self) -> &mut PeerManager<TSpec> {
        &mut self.swarm.behaviour_mut().peer_manager
    }

    /// The routing pub-sub mechanism for eth2.
    pub fn gossipsub(&self) -> &Gossipsub {
        &self.swarm.behaviour().gossipsub
    }
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub fn eth2_rpc(&self) -> &RPC<RequestId<AppReqId>, TSpec> {
        &self.swarm.behaviour().eth2_rpc
    }
    /// Discv5 Discovery protocol.
    pub fn discovery(&self) -> &Discovery<TSpec> {
        &self.swarm.behaviour().discovery
    }
    /// Provides IP addresses and peer information.
    pub fn identify(&self) -> &identify::Behaviour {
        &self.swarm.behaviour().identify
    }
    /// The peer manager that keeps track of peer's reputation and status.
    pub fn peer_manager(&self) -> &PeerManager<TSpec> {
        &self.swarm.behaviour().peer_manager
    }

    /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> Enr {
        self.network_globals.local_enr()
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

    /// Subscribe to all required topics for the `new_fork` with the given `new_fork_digest`.
    pub fn subscribe_new_fork_topics(&mut self, new_fork: ForkName, new_fork_digest: [u8; 4]) {
        // Subscribe to existing topics with new fork digest
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        for mut topic in subscriptions.into_iter() {
            topic.fork_digest = new_fork_digest;
            self.subscribe(topic);
        }

        // Subscribe to core topics for the new fork
        for kind in fork_core_topics::<TSpec>(&new_fork, &self.fork_context.spec) {
            let topic = GossipTopic::new(kind, GossipEncoding::default(), new_fork_digest);
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

    /// Remove topic weight from all topics that don't have the given fork digest.
    pub fn remove_topic_weight_except(&mut self, except: [u8; 4]) {
        let new_param = TopicScoreParams {
            topic_weight: 0.0,
            ..Default::default()
        };
        let subscriptions = self.network_globals.gossipsub_subscriptions.read().clone();
        for topic in subscriptions
            .iter()
            .filter(|topic| topic.fork_digest != except)
        {
            let libp2p_topic: Topic = topic.clone().into();
            match self
                .gossipsub_mut()
                .set_topic_params(libp2p_topic, new_param.clone())
            {
                Ok(_) => debug!(self.log, "Removed topic weight"; "topic" => %topic),
                Err(e) => {
                    warn!(self.log, "Failed to remove topic weight"; "topic" => %topic, "error" => e)
                }
            }
        }
    }

    /// Returns the scoring parameters for a topic if set.
    pub fn get_topic_params(&self, topic: GossipTopic) -> Option<&TopicScoreParams> {
        self.swarm
            .behaviour()
            .gossipsub
            .get_topic_params(&topic.into())
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

        match self.gossipsub_mut().subscribe(&topic) {
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
        let libp2p_topic: Topic = topic.clone().into();

        match self.gossipsub_mut().unsubscribe(&libp2p_topic) {
            Err(_) => {
                warn!(self.log, "Failed to unsubscribe from topic"; "topic" => %libp2p_topic);
                false
            }
            Ok(v) => {
                // Inform the network
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
                if let Err(e) = self
                    .gossipsub_mut()
                    .publish(Topic::from(topic.clone()), message_data.clone())
                {
                    match e {
                        PublishError::Duplicate => {
                            debug!(
                                self.log,
                                "Attempted to publish duplicate message";
                                "kind" => %topic.kind(),
                            );
                        }
                        ref e => {
                            warn!(
                                self.log,
                                "Could not publish message";
                                "error" => ?e,
                                "kind" => %topic.kind(),
                            );
                        }
                    }

                    // add to metrics
                    match topic.kind() {
                        GossipKind::Attestation(subnet_id) => {
                            if let Some(v) = metrics::get_int_gauge(
                                &metrics::FAILED_ATTESTATION_PUBLISHES_PER_SUBNET,
                                &[subnet_id.as_ref()],
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

                    if let PublishError::InsufficientPeers = e {
                        self.gossip_cache.insert(topic, message_data);
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

        if let Err(e) = self.gossipsub_mut().report_message_validation_result(
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

        self.gossipsub_mut()
            .set_topic_params(get_topic(GossipKind::BeaconBlock), beacon_block_params)?;

        self.gossipsub_mut().set_topic_params(
            get_topic(GossipKind::BeaconAggregateAndProof),
            beacon_aggregate_proof_params,
        )?;

        for i in 0..self.score_settings.attestation_subnet_count() {
            self.gossipsub_mut().set_topic_params(
                get_topic(GossipKind::Attestation(SubnetId::new(i))),
                beacon_attestation_subnet_params.clone(),
            )?;
        }

        Ok(())
    }

    /* Eth2 RPC behaviour functions */

    /// Send a request to a peer over RPC.
    pub fn send_request(&mut self, peer_id: PeerId, request_id: AppReqId, request: Request) {
        self.eth2_rpc_mut().send_request(
            peer_id,
            RequestId::Application(request_id),
            request.into(),
        )
    }

    /// Send a successful response to a peer over RPC.
    pub fn send_response(&mut self, peer_id: PeerId, id: PeerRequestId, response: Response<TSpec>) {
        self.eth2_rpc_mut()
            .send_response(peer_id, id, response.into())
    }

    /// Inform the peer that their request produced an error.
    pub fn send_error_response(
        &mut self,
        peer_id: PeerId,
        id: PeerRequestId,
        error: RPCResponseErrorCode,
        reason: String,
    ) {
        self.eth2_rpc_mut().send_response(
            peer_id,
            id,
            RPCCodedResponse::Error(error, reason.into()),
        )
    }

    /* Peer management functions */

    pub fn testing_dial(&mut self, addr: Multiaddr) -> Result<(), libp2p::swarm::DialError> {
        self.swarm.dial(addr)
    }

    pub fn report_peer(
        &mut self,
        peer_id: &PeerId,
        action: PeerAction,
        source: ReportSource,
        msg: &'static str,
    ) {
        self.peer_manager_mut()
            .report_peer(peer_id, action, source, None, msg);
    }

    /// Disconnects from a peer providing a reason.
    ///
    /// This will send a goodbye, disconnect and then ban the peer.
    /// This is fatal for a peer, and should be used in unrecoverable circumstances.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        self.peer_manager_mut()
            .goodbye_peer(peer_id, reason, source);
    }

    /// Returns an iterator over all enr entries in the DHT.
    pub fn enr_entries(&self) -> Vec<Enr> {
        self.discovery().table_entries_enr()
    }

    /// Add an ENR to the routing table of the discovery mechanism.
    pub fn add_enr(&mut self, enr: Enr) {
        self.discovery_mut().add_enr(enr);
    }

    /// Updates a subnet value to the ENR attnets/syncnets bitfield.
    ///
    /// The `value` is `true` if a subnet is being added and false otherwise.
    pub fn update_enr_subnet(&mut self, subnet_id: Subnet, value: bool) {
        if let Err(e) = self.discovery_mut().update_enr_bitfield(subnet_id, value) {
            crit!(self.log, "Could not update ENR bitfield"; "error" => e);
        }
        // update the local meta data which informs our peers of the update during PINGS
        self.update_metadata_bitfields();
    }

    /// Attempts to discover new peers for a given subnet. The `min_ttl` gives the time at which we
    /// would like to retain the peers for.
    pub fn discover_subnet_peers(&mut self, subnets_to_discover: Vec<SubnetDiscovery>) {
        // If discovery is not started or disabled, ignore the request
        if !self.discovery().started {
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
            self.discovery_mut().discover_subnet_peers(filtered);
        }
    }

    /// Updates the local ENR's "eth2" field with the latest EnrForkId.
    pub fn update_fork_version(&mut self, enr_fork_id: EnrForkId) {
        self.discovery_mut().update_eth2_enr(enr_fork_id.clone());

        // update the local reference
        self.enr_fork_id = enr_fork_id;
    }

    /* Private internal functions */

    /// Updates the current meta data of the node to match the local ENR.
    fn update_metadata_bitfields(&mut self) {
        let local_attnets = self
            .discovery_mut()
            .local_enr()
            .attestation_bitfield::<TSpec>()
            .expect("Local discovery must have attestation bitfield");

        let local_syncnets = self
            .discovery_mut()
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
        utils::save_metadata_to_disk(
            &self.network_dir,
            self.network_globals.local_metadata.read().clone(),
            &self.log,
        );
    }

    /// Sends a Ping request to the peer.
    fn ping(&mut self, peer_id: PeerId) {
        let ping = crate::rpc::Ping {
            data: *self.network_globals.local_metadata.read().seq_number(),
        };
        trace!(self.log, "Sending Ping"; "peer_id" => %peer_id);
        let id = RequestId::Internal;
        self.eth2_rpc_mut()
            .send_request(peer_id, id, OutboundRequest::Ping(ping));
    }

    /// Sends a Pong response to the peer.
    fn pong(&mut self, id: PeerRequestId, peer_id: PeerId) {
        let ping = crate::rpc::Ping {
            data: *self.network_globals.local_metadata.read().seq_number(),
        };
        trace!(self.log, "Sending Pong"; "request_id" => id.1, "peer_id" => %peer_id);
        let event = RPCCodedResponse::Success(RPCResponse::Pong(ping));
        self.eth2_rpc_mut().send_response(peer_id, id, event);
    }

    /// Sends a METADATA request to a peer.
    fn send_meta_data_request(&mut self, peer_id: PeerId) {
        // We always prefer sending V2 requests
        let event = OutboundRequest::MetaData(MetadataRequest::new_v2());
        self.eth2_rpc_mut()
            .send_request(peer_id, RequestId::Internal, event);
    }

    /// Sends a METADATA response to a peer.
    fn send_meta_data_response(
        &mut self,
        req: MetadataRequest<TSpec>,
        id: PeerRequestId,
        peer_id: PeerId,
    ) {
        let metadata = self.network_globals.local_metadata.read().clone();
        let metadata = match req {
            MetadataRequest::V1(_) => metadata.metadata_v1(),
            MetadataRequest::V2(_) => metadata,
        };
        let event = RPCCodedResponse::Success(RPCResponse::MetaData(metadata));
        self.eth2_rpc_mut().send_response(peer_id, id, event);
    }

    // RPC Propagation methods
    /// Queues the response to be sent upwards as long at it was requested outside the Behaviour.
    #[must_use = "return the response"]
    fn build_response(
        &mut self,
        id: RequestId<AppReqId>,
        peer_id: PeerId,
        response: Response<TSpec>,
    ) -> Option<NetworkEvent<AppReqId, TSpec>> {
        match id {
            RequestId::Application(id) => Some(NetworkEvent::ResponseReceived {
                peer_id,
                id,
                response,
            }),
            RequestId::Internal => None,
        }
    }

    /// Convenience function to propagate a request.
    #[must_use = "actually return the event"]
    fn build_request(
        &mut self,
        id: PeerRequestId,
        peer_id: PeerId,
        request: Request,
    ) -> NetworkEvent<AppReqId, TSpec> {
        // Increment metrics
        match &request {
            Request::Status(_) => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["status"])
            }
            Request::LightClientBootstrap(_) => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["light_client_bootstrap"])
            }
            Request::BlocksByRange { .. } => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["blocks_by_range"])
            }
            Request::BlocksByRoot { .. } => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["blocks_by_root"])
            }
            Request::BlobsByRange { .. } => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["blobs_by_range"])
            }
            Request::BlobsByRoot { .. } => {
                metrics::inc_counter_vec(&metrics::TOTAL_RPC_REQUESTS, &["blobs_by_root"])
            }
        }
        NetworkEvent::RequestReceived {
            peer_id,
            id,
            request,
        }
    }

    /// Dial cached Enrs in discovery service that are in the given `subnet_id` and aren't
    /// in Connected, Dialing or Banned state.
    fn dial_cached_enrs_in_subnet(&mut self, subnet: Subnet) {
        let predicate = subnet_predicate::<TSpec>(vec![subnet], &self.log);
        let peers_to_dial: Vec<Enr> = self
            .discovery()
            .cached_enrs()
            .filter_map(|(_peer_id, enr)| {
                if predicate(enr) {
                    Some(enr.clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove the ENR from the cache to prevent continual re-dialing on disconnects
        for enr in peers_to_dial {
            self.discovery_mut().remove_cached_enr(&enr.peer_id());
            let peer_id = enr.peer_id();
            if self.peer_manager_mut().dial_peer(enr) {
                debug!(self.log, "Dialing cached ENR peer"; "peer_id" => %peer_id);
            }
        }
    }

    /* Sub-behaviour event handling functions */

    /// Handle a gossipsub event.
    fn inject_gs_event(
        &mut self,
        event: gossipsub::Event,
    ) -> Option<NetworkEvent<AppReqId, TSpec>> {
        match event {
            gossipsub::Event::Message {
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
                        if let Err(e) = self.gossipsub_mut().report_message_validation_result(
                            &id,
                            &propagation_source,
                            MessageAcceptance::Reject,
                        ) {
                            warn!(self.log, "Failed to report message validation"; "message_id" => %id, "peer_id" => %propagation_source, "error" => ?e);
                        }
                    }
                    Ok(msg) => {
                        // Notify the network
                        return Some(NetworkEvent::PubsubMessage {
                            id,
                            source: propagation_source,
                            topic: gs_msg.topic,
                            message: msg,
                        });
                    }
                }
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                if let Ok(topic) = GossipTopic::decode(topic.as_str()) {
                    if let Some(subnet_id) = topic.subnet_id() {
                        self.network_globals
                            .peers
                            .write()
                            .add_subscription(&peer_id, subnet_id);
                    }
                    // Try to send the cached messages for this topic
                    if let Some(msgs) = self.gossip_cache.retrieve(&topic) {
                        for data in msgs {
                            let topic_str: &str = topic.kind().as_ref();
                            match self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(Topic::from(topic.clone()), data)
                            {
                                Ok(_) => {
                                    debug!(
                                        self.log,
                                        "Gossip message published on retry";
                                        "topic" => topic_str
                                    );
                                    metrics::inc_counter_vec(
                                        &metrics::GOSSIP_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    );
                                }
                                Err(PublishError::Duplicate) => {
                                    debug!(
                                        self.log,
                                        "Gossip message publish ignored on retry";
                                        "reason" => "duplicate",
                                        "topic" => topic_str
                                    );
                                    metrics::inc_counter_vec(
                                        &metrics::GOSSIP_FAILED_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        self.log,
                                        "Gossip message publish failed on retry";
                                        "topic" => topic_str,
                                        "error" => %e
                                    );
                                    metrics::inc_counter_vec(
                                        &metrics::GOSSIP_FAILED_LATE_PUBLISH_PER_TOPIC_KIND,
                                        &[topic_str],
                                    );
                                }
                            }
                        }
                    }
                }
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                if let Some(subnet_id) = subnet_from_topic_hash(&topic) {
                    self.network_globals
                        .peers
                        .write()
                        .remove_subscription(&peer_id, &subnet_id);
                }
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                debug!(self.log, "Peer does not support gossipsub"; "peer_id" => %peer_id);
                self.peer_manager_mut().report_peer(
                    &peer_id,
                    PeerAction::Fatal,
                    ReportSource::Gossipsub,
                    Some(GoodbyeReason::Unknown),
                    "does_not_support_gossipsub",
                );
            }
            gossipsub::Event::SlowPeer {
                peer_id,
                failed_messages,
            } => {
                debug!(self.log, "Slow gossipsub peer"; "peer_id" => %peer_id, "publish" => failed_messages.publish, "forward" => failed_messages.forward, "priority" => failed_messages.priority, "non_priority" => failed_messages.non_priority);
                // Punish the peer if it cannot handle priority messages
                if failed_messages.total_timeout() > 10 {
                    debug!(self.log, "Slow gossipsub peer penalized for priority failure"; "peer_id" => %peer_id);
                    self.peer_manager_mut().report_peer(
                        &peer_id,
                        PeerAction::HighToleranceError,
                        ReportSource::Gossipsub,
                        None,
                        "publish_timeout_penalty",
                    );
                } else if failed_messages.total_queue_full() > 10 {
                    debug!(self.log, "Slow gossipsub peer penalized for send queue full"; "peer_id" => %peer_id);
                    self.peer_manager_mut().report_peer(
                        &peer_id,
                        PeerAction::HighToleranceError,
                        ReportSource::Gossipsub,
                        None,
                        "queue_full_penalty",
                    );
                }
            }
        }
        None
    }

    /// Handle an RPC event.
    fn inject_rpc_event(
        &mut self,
        event: RPCMessage<RequestId<AppReqId>, TSpec>,
    ) -> Option<NetworkEvent<AppReqId, TSpec>> {
        let peer_id = event.peer_id;

        if !self.peer_manager().is_connected(&peer_id) {
            debug!(
                self.log,
                "Ignoring rpc message of disconnecting peer";
                event
            );
            return None;
        }

        let handler_id = event.conn_id;
        // The METADATA and PING RPC responses are handled within the behaviour and not propagated
        match event.event {
            HandlerEvent::Err(handler_err) => {
                match handler_err {
                    HandlerErr::Inbound {
                        id: _,
                        proto,
                        error,
                    } => {
                        // Inform the peer manager of the error.
                        // An inbound error here means we sent an error to the peer, or the stream
                        // timed out.
                        self.peer_manager_mut().handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Incoming,
                        );
                        None
                    }
                    HandlerErr::Outbound { id, proto, error } => {
                        // Inform the peer manager that a request we sent to the peer failed
                        self.peer_manager_mut().handle_rpc_error(
                            &peer_id,
                            proto,
                            &error,
                            ConnectionDirection::Outgoing,
                        );
                        // inform failures of requests coming outside the behaviour
                        if let RequestId::Application(id) = id {
                            Some(NetworkEvent::RPCFailed { peer_id, id, error })
                        } else {
                            None
                        }
                    }
                }
            }
            HandlerEvent::Ok(RPCReceived::Request(id, request)) => {
                let peer_request_id = (handler_id, id);
                match request {
                    /* Behaviour managed protocols: Ping and Metadata */
                    InboundRequest::Ping(ping) => {
                        // inform the peer manager and send the response
                        self.peer_manager_mut().ping_request(&peer_id, ping.data);
                        // send a ping response
                        self.pong(peer_request_id, peer_id);
                        None
                    }
                    InboundRequest::MetaData(req) => {
                        // send the requested meta-data
                        self.send_meta_data_response(req, (handler_id, id), peer_id);
                        None
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
                        None
                    }
                    /* Protocols propagated to the Network */
                    InboundRequest::Status(msg) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager_mut().peer_statusd(&peer_id);
                        // propagate the STATUS message upwards
                        let event =
                            self.build_request(peer_request_id, peer_id, Request::Status(msg));
                        Some(event)
                    }
                    InboundRequest::BlocksByRange(req) => {
                        // Still disconnect the peer if the request is naughty.
                        let mut count = *req.count();
                        if *req.step() == 0 {
                            self.peer_manager_mut().handle_rpc_error(
                                &peer_id,
                                Protocol::BlocksByRange,
                                &RPCError::InvalidData(
                                    "Blocks by range with 0 step parameter".into(),
                                ),
                                ConnectionDirection::Incoming,
                            );
                            return None;
                        }
                        // return just one block in case the step parameter is used. https://github.com/ethereum/consensus-specs/pull/2856
                        if *req.step() > 1 {
                            count = 1;
                        }
                        let request = match req {
                            methods::OldBlocksByRangeRequest::V1(req) => Request::BlocksByRange(
                                BlocksByRangeRequest::new_v1(req.start_slot, count),
                            ),
                            methods::OldBlocksByRangeRequest::V2(req) => Request::BlocksByRange(
                                BlocksByRangeRequest::new(req.start_slot, count),
                            ),
                        };
                        let event = self.build_request(peer_request_id, peer_id, request);
                        Some(event)
                    }
                    InboundRequest::BlocksByRoot(req) => {
                        let event = self.build_request(
                            peer_request_id,
                            peer_id,
                            Request::BlocksByRoot(req),
                        );
                        Some(event)
                    }
                    InboundRequest::BlobsByRange(req) => {
                        let event = self.build_request(
                            peer_request_id,
                            peer_id,
                            Request::BlobsByRange(req),
                        );
                        Some(event)
                    }
                    InboundRequest::BlobsByRoot(req) => {
                        let event =
                            self.build_request(peer_request_id, peer_id, Request::BlobsByRoot(req));
                        Some(event)
                    }
                    InboundRequest::LightClientBootstrap(req) => {
                        let event = self.build_request(
                            peer_request_id,
                            peer_id,
                            Request::LightClientBootstrap(req),
                        );
                        Some(event)
                    }
                }
            }
            HandlerEvent::Ok(RPCReceived::Response(id, resp)) => {
                match resp {
                    /* Behaviour managed protocols */
                    RPCResponse::Pong(ping) => {
                        self.peer_manager_mut().pong_response(&peer_id, ping.data);
                        None
                    }
                    RPCResponse::MetaData(meta_data) => {
                        self.peer_manager_mut()
                            .meta_data_response(&peer_id, meta_data);
                        None
                    }
                    /* Network propagated protocols */
                    RPCResponse::Status(msg) => {
                        // inform the peer manager that we have received a status from a peer
                        self.peer_manager_mut().peer_statusd(&peer_id);
                        // propagate the STATUS message upwards
                        self.build_response(id, peer_id, Response::Status(msg))
                    }
                    RPCResponse::BlocksByRange(resp) => {
                        self.build_response(id, peer_id, Response::BlocksByRange(Some(resp)))
                    }
                    RPCResponse::BlobsByRange(resp) => {
                        self.build_response(id, peer_id, Response::BlobsByRange(Some(resp)))
                    }
                    RPCResponse::BlocksByRoot(resp) => {
                        self.build_response(id, peer_id, Response::BlocksByRoot(Some(resp)))
                    }
                    RPCResponse::BlobsByRoot(resp) => {
                        self.build_response(id, peer_id, Response::BlobsByRoot(Some(resp)))
                    }
                    // Should never be reached
                    RPCResponse::LightClientBootstrap(bootstrap) => {
                        self.build_response(id, peer_id, Response::LightClientBootstrap(bootstrap))
                    }
                }
            }
            HandlerEvent::Ok(RPCReceived::EndOfStream(id, termination)) => {
                let response = match termination {
                    ResponseTermination::BlocksByRange => Response::BlocksByRange(None),
                    ResponseTermination::BlocksByRoot => Response::BlocksByRoot(None),
                    ResponseTermination::BlobsByRange => Response::BlobsByRange(None),
                    ResponseTermination::BlobsByRoot => Response::BlobsByRoot(None),
                };
                self.build_response(id, peer_id, response)
            }
            HandlerEvent::Close(_) => {
                // NOTE: This is handled in the RPC behaviour.
                None
            }
        }
    }

    /// Handle an identify event.
    fn inject_identify_event(
        &mut self,
        event: identify::Event,
    ) -> Option<NetworkEvent<AppReqId, TSpec>> {
        match event {
            identify::Event::Received { peer_id, mut info } => {
                if info.listen_addrs.len() > MAX_IDENTIFY_ADDRESSES {
                    debug!(
                        self.log,
                        "More than 10 addresses have been identified, truncating"
                    );
                    info.listen_addrs.truncate(MAX_IDENTIFY_ADDRESSES);
                }
                // send peer info to the peer manager.
                self.peer_manager_mut().identify(&peer_id, &info);
            }
            identify::Event::Sent { .. } => {}
            identify::Event::Error { .. } => {}
            identify::Event::Pushed { .. } => {}
        }
        None
    }

    /// Handle a peer manager event.
    fn inject_pm_event(
        &mut self,
        event: PeerManagerEvent,
    ) -> Option<NetworkEvent<AppReqId, TSpec>> {
        match event {
            PeerManagerEvent::PeerConnectedIncoming(peer_id) => {
                Some(NetworkEvent::PeerConnectedIncoming(peer_id))
            }
            PeerManagerEvent::PeerConnectedOutgoing(peer_id) => {
                Some(NetworkEvent::PeerConnectedOutgoing(peer_id))
            }
            PeerManagerEvent::PeerDisconnected(peer_id) => {
                Some(NetworkEvent::PeerDisconnected(peer_id))
            }
            PeerManagerEvent::Banned(peer_id, associated_ips) => {
                self.discovery_mut().ban_peer(&peer_id, associated_ips);
                None
            }
            PeerManagerEvent::UnBanned(peer_id, associated_ips) => {
                self.discovery_mut().unban_peer(&peer_id, associated_ips);
                None
            }
            PeerManagerEvent::Status(peer_id) => {
                // it's time to status. We don't keep a beacon chain reference here, so we inform
                // the network to send a status to this peer
                Some(NetworkEvent::StatusPeer(peer_id))
            }
            PeerManagerEvent::DiscoverPeers(peers_to_find) => {
                // Peer manager has requested a discovery query for more peers.
                self.discovery_mut().discover_peers(peers_to_find);
                None
            }
            PeerManagerEvent::DiscoverSubnetPeers(subnets_to_discover) => {
                // Peer manager has requested a subnet discovery query for more peers.
                self.discover_subnet_peers(subnets_to_discover);
                None
            }
            PeerManagerEvent::Ping(peer_id) => {
                // send a ping request to this peer
                self.ping(peer_id);
                None
            }
            PeerManagerEvent::MetaData(peer_id) => {
                self.send_meta_data_request(peer_id);
                None
            }
            PeerManagerEvent::DisconnectPeer(peer_id, reason) => {
                debug!(self.log, "Peer Manager disconnecting peer";
                       "peer_id" => %peer_id, "reason" => %reason);
                // send one goodbye
                self.eth2_rpc_mut()
                    .shutdown(peer_id, RequestId::Internal, reason);
                None
            }
        }
    }

    fn inject_upnp_event(&mut self, event: libp2p::upnp::Event) {
        match event {
            libp2p::upnp::Event::NewExternalAddr(addr) => {
                info!(self.log, "UPnP route established"; "addr" => %addr);
                let mut iter = addr.iter();
                // Skip Ip address.
                iter.next();
                match iter.next() {
                    Some(multiaddr::Protocol::Udp(udp_port)) => match iter.next() {
                        Some(multiaddr::Protocol::QuicV1) => {
                            if let Err(e) = self.discovery_mut().update_enr_quic_port(udp_port) {
                                warn!(self.log, "Failed to update ENR"; "error" => e);
                            }
                        }
                        _ => {
                            trace!(self.log, "UPnP address mapped multiaddr from unknown transport"; "addr" => %addr)
                        }
                    },
                    Some(multiaddr::Protocol::Tcp(tcp_port)) => {
                        if let Err(e) = self.discovery_mut().update_enr_tcp_port(tcp_port) {
                            warn!(self.log, "Failed to update ENR"; "error" => e);
                        }
                    }
                    _ => {
                        trace!(self.log, "UPnP address mapped multiaddr from unknown transport"; "addr" => %addr);
                    }
                }
            }
            libp2p::upnp::Event::ExpiredExternalAddr(_) => {}
            libp2p::upnp::Event::GatewayNotFound => {
                info!(self.log, "UPnP not available");
            }
            libp2p::upnp::Event::NonRoutableGateway => {
                info!(
                    self.log,
                    "UPnP is available but gateway is not exposed to public network"
                );
            }
        }
    }

    /* Networking polling */

    /// Poll the p2p networking stack.
    ///
    /// This will poll the swarm and do maintenance routines.
    pub fn poll_network(&mut self, cx: &mut Context) -> Poll<NetworkEvent<AppReqId, TSpec>> {
        while let Poll::Ready(Some(swarm_event)) = self.swarm.poll_next_unpin(cx) {
            let maybe_event = match swarm_event {
                SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
                    // Handle sub-behaviour events.
                    BehaviourEvent::Gossipsub(ge) => self.inject_gs_event(ge),
                    BehaviourEvent::Eth2Rpc(re) => self.inject_rpc_event(re),
                    // Inform the peer manager about discovered peers.
                    //
                    // The peer manager will subsequently decide which peers need to be dialed and then dial
                    // them.
                    BehaviourEvent::Discovery(DiscoveredPeers { peers }) => {
                        self.peer_manager_mut().peers_discovered(peers);
                        None
                    }
                    BehaviourEvent::Identify(ie) => self.inject_identify_event(ie),
                    BehaviourEvent::PeerManager(pe) => self.inject_pm_event(pe),
                    BehaviourEvent::Upnp(e) => {
                        self.inject_upnp_event(e);
                        None
                    }
                    BehaviourEvent::ConnectionLimits(le) => void::unreachable(le),
                },
                SwarmEvent::ConnectionEstablished { .. } => None,
                SwarmEvent::ConnectionClosed { .. } => None,
                SwarmEvent::IncomingConnection {
                    local_addr,
                    send_back_addr,
                    connection_id: _,
                } => {
                    trace!(self.log, "Incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr);
                    None
                }
                SwarmEvent::IncomingConnectionError {
                    local_addr,
                    send_back_addr,
                    error,
                    connection_id: _,
                } => {
                    let error_repr = match error {
                        libp2p::swarm::ListenError::Aborted => {
                            "Incoming connection aborted".to_string()
                        }
                        libp2p::swarm::ListenError::WrongPeerId { obtained, endpoint } => {
                            format!("Wrong peer id, obtained {obtained}, endpoint {endpoint:?}")
                        }
                        libp2p::swarm::ListenError::LocalPeerId { endpoint } => {
                            format!("Dialing local peer id {endpoint:?}")
                        }
                        libp2p::swarm::ListenError::Denied { cause } => {
                            format!("Connection was denied with cause: {cause:?}")
                        }
                        libp2p::swarm::ListenError::Transport(t) => match t {
                            libp2p::TransportError::MultiaddrNotSupported(m) => {
                                format!("Transport error: Multiaddr not supported: {m}")
                            }
                            libp2p::TransportError::Other(e) => {
                                format!("Transport error: other: {e}")
                            }
                        },
                    };
                    debug!(self.log, "Failed incoming connection"; "our_addr" => %local_addr, "from" => %send_back_addr, "error" => error_repr);
                    None
                }
                SwarmEvent::OutgoingConnectionError {
                    peer_id: _,
                    error: _,
                    connection_id: _,
                } => {
                    // The Behaviour event is more general than the swarm event here. It includes
                    // connection failures. So we use that log for now, in the peer manager
                    // behaviour implementation.
                    None
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    Some(NetworkEvent::NewListenAddr(address))
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    debug!(self.log, "Listen address expired"; "address" => %address);
                    None
                }
                SwarmEvent::ListenerClosed {
                    addresses, reason, ..
                } => {
                    match reason {
                        Ok(_) => {
                            debug!(self.log, "Listener gracefully closed"; "addresses" => ?addresses)
                        }
                        Err(reason) => {
                            crit!(self.log, "Listener abruptly closed"; "addresses" => ?addresses, "reason" => ?reason)
                        }
                    };
                    if Swarm::listeners(&self.swarm).count() == 0 {
                        Some(NetworkEvent::ZeroListeners)
                    } else {
                        None
                    }
                }
                SwarmEvent::ListenerError { error, .. } => {
                    // this is non fatal, but we still check
                    warn!(self.log, "Listener error"; "error" => ?error);
                    if Swarm::listeners(&self.swarm).count() == 0 {
                        Some(NetworkEvent::ZeroListeners)
                    } else {
                        None
                    }
                }
                _ => {
                    // NOTE: SwarmEvent is a non exhaustive enum so updates should be based on
                    // release notes more than compiler feedback
                    None
                }
            };

            if let Some(ev) = maybe_event {
                return Poll::Ready(ev);
            }
        }

        // perform gossipsub score updates when necessary
        while self.update_gossipsub_scores.poll_tick(cx).is_ready() {
            let this = self.swarm.behaviour_mut();
            this.peer_manager.update_gossipsub_scores(&this.gossipsub);
        }

        // poll the gossipsub cache to clear expired messages
        while let Poll::Ready(Some(result)) = self.gossip_cache.poll_next_unpin(cx) {
            match result {
                Err(e) => warn!(self.log, "Gossip cache error"; "error" => e),
                Ok(expired_topic) => {
                    if let Some(v) = metrics::get_int_counter(
                        &metrics::GOSSIP_EXPIRED_LATE_PUBLISH_PER_TOPIC_KIND,
                        &[expired_topic.kind().as_ref()],
                    ) {
                        v.inc()
                    };
                }
            }
        }
        Poll::Pending
    }

    pub async fn next_event(&mut self) -> NetworkEvent<AppReqId, TSpec> {
        futures::future::poll_fn(|cx| self.poll_network(cx)).await
    }
}
