use crate::config::NetworkConfig;
use crate::rpc::{LeanBlocksByRootProtocol, RPCRequest, RPCResponse, SSZSnappyCodec};
use crate::status::{LeanStatusProtocol, StatusMessage, StatusSnappyCodec};
use crate::topics::{self, Topic};
use crate::peer_manager::{PeerCommand, PeerEvent, PeerManager};
use futures::StreamExt;
use lean_consensus::attestation::SignedAttestation;
use lean_consensus::lean_block::SignedLeanBlockWithAttestation;
use libp2p::identity::{self, Keypair};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    gossipsub::{self, MessageId},
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use sha2::{Digest, Sha256};
use snap::raw::{Decoder as RawDecoder, Encoder as RawEncoder};
use ssz::{Decode, Encode};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, info, trace, warn};
use types::EthSpec;
use crate::metrics;


/// Domain prefix for valid snappy-compressed messages per Eth2 networking spec
/// This is prepended to message data before hashing to create unique message IDs
const MESSAGE_DOMAIN_VALID_SNAPPY: &[u8] = &[0x01, 0x00, 0x00, 0x00];

#[derive(NetworkBehaviour)]
pub struct LeanBehaviour<E: EthSpec> {
    gossipsub: gossipsub::Behaviour,
    req_resp: request_response::Behaviour<SSZSnappyCodec<E>>,
    status_req_resp: request_response::Behaviour<StatusSnappyCodec>,
}

/// Messages received from the network that need to be processed
pub enum NetworkMessage<E: EthSpec> {
    /// Signed attestation received from network (peer_id is Some for network gossip)
    Attestation(Option<PeerId>, Arc<SignedAttestation>),
    /// Block received from network or to be published (peer_id is None for local)
    Block(Option<PeerId>, Arc<SignedLeanBlockWithAttestation<E>>),
    /// A peer connected (used to trigger sync/status handshake)
    PeerConnected(PeerId),
    /// A peer disconnected (used for status display / heuristics)
    PeerDisconnected(PeerId),
    /// Status response received from a peer.
    Status(PeerId, StatusMessage),
    /// Update the cached local status used for responding to inbound status requests.
    UpdateLocalStatus(StatusMessage),
    /// Request to send an RPC request to a peer
    SendRequest {
        peer_id: PeerId,
        request: RPCRequest,
    },
    /// Request to send a status request to a peer
    SendStatusRequest {
        peer_id: PeerId,
        status: StatusMessage,
    },
}

pub struct NetworkService<E: EthSpec> {
    swarm: Swarm<LeanBehaviour<E>>,
    /// Messages from network -> validator.
    ///
    /// This is bounded (created by the lean client) so we must avoid unbounded buffering here.
    /// The swarm event loop must not await on backpressure, so we `try_send` and drop on overflow.
    network_recv: mpsc::Sender<NetworkMessage<E>>,
    /// Messages from validator -> network.
    network_send: mpsc::Receiver<NetworkMessage<E>>,
    /// Peer manager event sender (network -> peer manager).
    peer_manager_evt_tx: mpsc::Sender<PeerEvent>,
    /// Peer manager command receiver (peer manager -> network).
    peer_manager_cmd_rx: mpsc::Receiver<PeerCommand>,
    /// Peer manager instance (spawned when `start()` is called).
    peer_manager: Option<PeerManager>,
    /// Network name used for topic encoding
    network_name: String,
    /// Cached local status (updated by validator service) used to reply to inbound status requests.
    local_status: StatusMessage,
}

impl<E: EthSpec> NetworkService<E> {
    pub fn new(
        config: NetworkConfig,
        network_recv: mpsc::Sender<NetworkMessage<E>>,
        network_send: mpsc::Receiver<NetworkMessage<E>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let NetworkConfig {
            listen_port,
            bootstrap_nodes: bootstrap_node_strings,
            node_key,
            network_name,
        } = config;

        let local_key = match node_key {
            Some(mut key_bytes) => {
                if key_bytes.len() != 32 {
                    return Err(format!(
                        "Libp2p private key must be 32 bytes, got {} bytes",
                        key_bytes.len()
                    )
                    .into());
                }
                let secret = identity::secp256k1::SecretKey::try_from_bytes(&mut key_bytes[..])
                    .map_err(|e| {
                        format!("Failed to parse libp2p secp256k1 private key: {:?}", e)
                    })?;
                let kp: identity::secp256k1::Keypair = secret.into();
                Keypair::from(kp)
            }
            None => identity::Keypair::generate_ed25519(),
        };
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer id: {:?}", local_peer_id);

        // Use QUIC transport (handles multiplexing natively)
        let transport = libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(&local_key))
            .map(|(peer_id, conn), _| (peer_id, libp2p::core::muxing::StreamMuxerBox::new(conn)))
            .boxed();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            // Zeam (and the other lean clients) use anonymous gossipsub messages.
            // If we publish signed gossipsub messages, peers configured for anonymous validation
            // may drop our messages.
            .validation_mode(gossipsub::ValidationMode::Anonymous)
            .message_id_fn(|message: &gossipsub::Message| {
                // Use SHA256 hash of topic + data with domain prefix for message ID
                // This matches the Eth2 networking spec for message deduplication
                let topic_bytes = message.topic.as_str().as_bytes();
                let mut digest = vec![];
                digest.extend_from_slice(MESSAGE_DOMAIN_VALID_SNAPPY);
                digest.extend_from_slice(&topic_bytes.len().to_le_bytes());
                digest.extend_from_slice(topic_bytes);
                digest.extend_from_slice(&message.data);

                let hash = Sha256::digest(&digest);
                MessageId::from(&hash[..20])
            })
            .build()
            .map_err(|e| format!("Failed to build gossipsub config: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            // Match Zeam: publish anonymous gossipsub messages for interoperability.
            gossipsub::MessageAuthenticity::Anonymous,
            gossipsub_config,
        )
        .map_err(|e| format!("Failed to create gossipsub behaviour: {}", e))?;

        let req_resp = request_response::Behaviour::new(
            vec![(LeanBlocksByRootProtocol, ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        // Status is used to learn a peer's head after downtime and trigger backfill.
        // We also support inbound requests so peers like Zeam don't disconnect on status handshake.
        let status_req_resp = request_response::Behaviour::new(
            vec![(LeanStatusProtocol, ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        let behaviour = LeanBehaviour {
            gossipsub,
            req_resp,
            status_req_resp,
        };

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );

        let listen_addr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", listen_port)
            .parse()
            .map_err(|e| format!("Invalid listen address: {}", e))?;

        swarm.listen_on(listen_addr)?;

        let encoded_topics = topics::get_topics(&network_name);
        info!("Subscribing to gossipsub topics: {:?}", encoded_topics);
        for topic_str in encoded_topics.iter() {
            let topic = gossipsub::IdentTopic::new(topic_str.clone());
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .map_err(|e| format!("Failed to subscribe to topic {}: {}", topic_str, e))?;
        }

        // Collect bootstrap peers for the peer manager.
        let mut bootstrap_peers: Vec<(PeerId, Multiaddr)> = Vec::new();
        for bootstrap_addr_raw in bootstrap_node_strings.iter() {
            let bootstrap_addr_str = bootstrap_addr_raw.trim();

            let multiaddr = if bootstrap_addr_str.starts_with("enr:") {
                match crate::bootstrap::parse_enr_to_multiaddr(bootstrap_addr_str) {
                    Ok(multiaddr) => multiaddr,
                    Err(e) => {
                        warn!("Invalid bootstrap ENR {}: {}", bootstrap_addr_str, e);
                        continue;
                    }
                }
            } else {
                match bootstrap_addr_str.parse::<Multiaddr>() {
                    Ok(multiaddr) => multiaddr,
                    Err(e) => {
                        warn!(
                            "Invalid bootstrap node address {}: {}",
                            bootstrap_addr_str, e
                        );
                        continue;
                    }
                }
            };

            if let Some(peer_in_addr) = peer_id_from_multiaddr(multiaddr.clone())
                && peer_in_addr != local_peer_id
            {
                bootstrap_peers.push((peer_in_addr, multiaddr.clone()));
            }
        }

        info!("Initialized {} bootstrap peers for peer manager", bootstrap_peers.len());

        let (peer_manager_evt_tx, peer_manager_evt_rx) = mpsc::channel(64);
        let (peer_manager_cmd_tx, peer_manager_cmd_rx) = mpsc::channel(64);
        let peer_manager = PeerManager::new(
            bootstrap_peers,
            Duration::from_secs(1),
            Duration::from_secs(60),
            peer_manager_evt_rx,
            peer_manager_cmd_tx,
        );

        Ok(Self {
            swarm,
            network_recv,
            network_send,
            peer_manager_evt_tx,
            peer_manager_cmd_rx,
            peer_manager: Some(peer_manager),
            network_name,
            local_status: StatusMessage {
                finalized_root: types::Hash256::ZERO,
                finalized_slot: 0,
                head_root: types::Hash256::ZERO,
                head_slot: 0,
            },
        })
    }

    fn try_forward_to_validator(&self, msg: NetworkMessage<E>, kind: &'static str) {
        match self.network_recv.try_send(msg) {
            Ok(()) => {}
            Err(TrySendError::Full(_msg)) => {
                // Drop on overflow to avoid unbounded memory growth.
                metrics::inc_counter_vec(
                    &*metrics::LEAN_P2P_TO_VALIDATOR_DROPPED_TOTAL,
                    &["channel_full", kind],
                );
            }
            Err(TrySendError::Closed(_msg)) => {
                warn!("Validator channel closed; dropping network message");
                metrics::inc_counter_vec(
                    &*metrics::LEAN_P2P_TO_VALIDATOR_DROPPED_TOTAL,
                    &["channel_closed", kind],
                );
            }
        }
    }

    /// Decode message based on topic and create appropriate NetworkMessage
    /// Messages are expected to be snappy-compressed
    fn decode_network_message(
        &self,
        topic: &str,
        data: &[u8],
        peer_id: PeerId,
    ) -> Option<NetworkMessage<E>> {
        let Some(base_topic) = topics::parse_topic_name(topic, &self.network_name) else {
            debug!("Unknown topic format: {}", topic);
            return None;
        };

        metrics::inc_counter_vec(&*metrics::LEAN_P2P_MESSAGES_RECEIVED_TOTAL, &[topic]);


        // Decompress snappy-compressed message
        let decompressed = match self.decompress_snappy(data) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to decompress snappy message: {}", e);
                return None;
            }
        };

        match base_topic {
            Topic::Block => match SignedLeanBlockWithAttestation::from_ssz_bytes(&decompressed) {
                Ok(block) => {
                    debug!("Successfully decoded lean block from network");
                    Some(NetworkMessage::Block(Some(peer_id), Arc::new(block)))
                }
                Err(e) => {
                    warn!("Failed to decode lean block: {:?}", e);
                    None
                }
            },
            Topic::Attestation => match SignedAttestation::from_ssz_bytes(&decompressed) {
                Ok(signed_attestation) => {
                    debug!("Successfully decoded signed lean attestation from network");
                    Some(NetworkMessage::Attestation(
                        Some(peer_id),
                        Arc::new(signed_attestation),
                    ))
                }
                Err(e) => {
                    warn!("Failed to decode signed lean attestation: {:?}", e);
                    None
                }
            },
        }
    }

    /// Decompress raw (unframed) snappy-compressed data
    /// Gossipsub uses raw snappy format per Eth2 networking spec
    fn decompress_snappy(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut decoder = RawDecoder::new();
        decoder
            .decompress_vec(data)
            .map_err(|e| format!("Snappy decompression failed: {}", e))
    }

    /// Compress data using raw (unframed) snappy compression
    /// Gossipsub uses raw snappy format per Eth2 networking spec
    fn compress_snappy(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut encoder = RawEncoder::new();
        encoder
            .compress_vec(data)
            .map_err(|e| format!("Snappy compression failed: {}", e))
    }

    pub async fn start(mut self) {
        info!("Network service started");
        // Start the async peer manager (handles exponential backoff and dialing).
        if let Some(pm) = self.peer_manager.take() {
            tokio::spawn(pm.run());
        }

        loop {
            tokio::select! {
                // Peer manager dial commands.
                Some(cmd) = self.peer_manager_cmd_rx.recv() => {
                    match cmd {
                        PeerCommand::Dial(addr) => {
                            if let Err(e) = self.swarm.dial(addr.clone()) {
                                warn!("Failed to dial {}: {:?}", addr, e);
                            } else {
                                debug!("Dialing peer via peer manager: {}", addr);
                            }
                        }
                    }
                }

                // Handle messages to publish or requests to send
                Some(msg) = self.network_send.recv() => {
                    self.handle_command(msg).await;
                }

                // Handle swarm events
                event = self.swarm.select_next_some() => {
            match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on: {:?}", address);
                }
                SwarmEvent::Behaviour(event) => {
                    match event {
                        LeanBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source,
                            message,
                            message_id,
                        }) => {
                            debug!(
                                "Received gossipsub message from {:?} on topic {:?}, message_id: {:?}",
                                propagation_source, message.topic, message_id
                            );

                            // Decode the message based on topic
                            if let Some(network_msg) =
                                self.decode_network_message(message.topic.as_str(), &message.data, propagation_source)
                            {
                                match &network_msg {
                                    NetworkMessage::Attestation(_, _) => {
                                        info!("Forwarding attestation to attestation service");
                                    }
                                    NetworkMessage::Block(_, _) => {
                                        info!("Forwarding block to attestation service");
                                    }
                                    NetworkMessage::PeerConnected(_) => {}
                                    NetworkMessage::PeerDisconnected(_) => {}
                                    NetworkMessage::Status(_, _) => {}
                                    NetworkMessage::UpdateLocalStatus(_) => {}
                                    NetworkMessage::SendRequest { .. } => {
                                        warn!("Received SendRequest from network decode (unexpected)");
                                    }
                                    NetworkMessage::SendStatusRequest { .. } => {
                                        warn!("Received SendStatusRequest from network decode (unexpected)");
                                    }
                                }

                                let kind = match &network_msg {
                                    NetworkMessage::Attestation(_, _) => "attestation",
                                    NetworkMessage::Block(_, _) => "block",
                                    NetworkMessage::PeerConnected(_) => "peer_connected",
                                    NetworkMessage::PeerDisconnected(_) => "peer_disconnected",
                                    NetworkMessage::Status(_, _) => "status",
                                    NetworkMessage::UpdateLocalStatus(_) => "update_local_status",
                                    NetworkMessage::SendRequest { .. } => "send_request",
                                    NetworkMessage::SendStatusRequest { .. } => "send_status_request",
                                };
                                self.try_forward_to_validator(network_msg, kind);
                            }
                        }
                        LeanBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                            debug!("Peer {:?} subscribed to topic: {:?}", peer_id, topic);
                        }
                        LeanBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                            debug!("Peer {:?} unsubscribed from topic: {:?}", peer_id, topic);
                        }
                        LeanBehaviourEvent::Gossipsub(other_gossipsub_event) => {
                            trace!("Gossipsub behaviour event: {:?}", other_gossipsub_event);
                        }
                        LeanBehaviourEvent::ReqResp(request_response::Event::Message {
                            peer,
                            message: request_response::Message::Response { response, .. },
                            ..
                        }) => {
                            match response {
                                RPCResponse::BlocksByRoot(block) => {
                                    info!(
                                        slot = block.message.block.slot.0,
                                        peer = ?peer,
                                        "Received BlocksByRoot response"
                                    );
                                    self.try_forward_to_validator(
                                        NetworkMessage::Block(Some(peer), Arc::new(block)),
                                        "block_rpc",
                                    );
                                }
                            }
                        }
                        LeanBehaviourEvent::StatusReqResp(request_response::Event::Message {
                            peer,
                            message,
                            ..
                        }) => {
                            match message {
                                request_response::Message::Response { response, .. } => {
                                    debug!(
                                        peer = ?peer,
                                        head_slot = response.head_slot,
                                        finalized_slot = response.finalized_slot,
                                        "Received Status response"
                                    );
                                    let _ = self
                                        .peer_manager_evt_tx
                                        .try_send(PeerEvent::StatusReceived(peer, response.clone()));
                                    self.try_forward_to_validator(
                                        NetworkMessage::Status(peer, response),
                                        "status",
                                    );
                                }
                                request_response::Message::Request {
                                    request, channel, ..
                                } => {
                                    debug!(
                                        peer = ?peer,
                                        req_head_slot = request.head_slot,
                                        req_finalized_slot = request.finalized_slot,
                                        "Received Status request"
                                    );
                                    let resp = self.local_status.clone();
                                    if let Err(e) = self
                                        .swarm
                                        .behaviour_mut()
                                        .status_req_resp
                                        .send_response(channel, resp)
                                    {
                                        warn!("Failed to send status response: {:?}", e);
                                    }
                                }
                            }
                        }
                        LeanBehaviourEvent::ReqResp(other_event) => {
                            trace!("ReqResp behaviour event: {:?}", other_event);
                        }
                        LeanBehaviourEvent::StatusReqResp(other_event) => {
                            trace!("StatusReqResp behaviour event: {:?}", other_event);
                        }
                    }
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint,
                    ..
                } => {
                    info!(
                        "Connection established with peer: {:?} at {:?}",
                        peer_id, endpoint
                    );
                    metrics::inc_gauge(&*metrics::LEAN_P2P_PEERS);
                    let _ = self.peer_manager_evt_tx.try_send(PeerEvent::Connected(peer_id));

                    // Notify validator service so it can trigger sync/status handshake.
                    self.try_forward_to_validator(NetworkMessage::PeerConnected(peer_id), "peer_connected");
                }
                SwarmEvent::ConnectionClosed {
                    peer_id, cause, ..
                } => {
                    debug!("Connection closed with peer: {:?}, cause: {:?}", peer_id, cause);
                    metrics::dec_gauge(&*metrics::LEAN_P2P_PEERS);
                    // Notify validator service (for display / peer tracking).
                    self.try_forward_to_validator(NetworkMessage::PeerDisconnected(peer_id), "peer_disconnected");
                    let _ = self.peer_manager_evt_tx.try_send(PeerEvent::Disconnected(peer_id));
                }


                SwarmEvent::IncomingConnection { .. } => {
                    debug!("Incoming connection");
                }
                SwarmEvent::IncomingConnectionError { error, .. } => {
                    warn!("Incoming connection error: {:?}", error);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    warn!("Outgoing connection error to {:?}: {:?}", peer_id, error);
                    if let Some(peer_id) = peer_id {
                        let _ = self.peer_manager_evt_tx.try_send(PeerEvent::Disconnected(peer_id));
                    }
                }
                SwarmEvent::Dialing { .. } => {
                    debug!("Dialing peer");
                }
                _ => {}
            }
                }
            }
        }
    }

    /// Handles a command from the validator service (publish message or send request)
    async fn handle_command(&mut self, msg: NetworkMessage<E>) {
        match msg {
            NetworkMessage::SendRequest { peer_id, request } => {
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .send_request(&peer_id, request);
                debug!(?peer_id, ?request_id, "Sent RPC request");
            }
            NetworkMessage::SendStatusRequest { peer_id, status } => {
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .status_req_resp
                    .send_request(&peer_id, status);
                debug!(?peer_id, ?request_id, "Sent status request");
            }
            NetworkMessage::UpdateLocalStatus(status) => {
                self.local_status = status;
            }
            NetworkMessage::Attestation(_, signed_attestation) => {
                info!(
                    slot = signed_attestation.message.attestation_data.slot.0,
                    validator_id = signed_attestation.message.validator_id,
                    "Publishing attestation to network"
                );
                self.publish_gossip_data(Topic::Attestation, signed_attestation.as_ssz_bytes());
            }
            NetworkMessage::Block(_, block) => {
                info!(
                    slot = block.message.block.slot.0,
                    "Publishing block to network"
                );
                self.publish_gossip_data(Topic::Block, block.as_ssz_bytes());
            }
            NetworkMessage::PeerConnected(_) | NetworkMessage::Status(_, _) => {
                // Not commands for the network service.
            }
            NetworkMessage::PeerDisconnected(_) => {}
        }
    }

    /// Publishes data to the gossipsub network
    fn publish_gossip_data(&mut self, topic_variant: Topic, data: Vec<u8>) {
        // Compress data using snappy before publishing (required by Eth2 networking spec)
        let compressed_data = match self.compress_snappy(&data) {
            Ok(compressed) => compressed,
            Err(e) => {
                warn!("Failed to compress message for publishing: {}", e);
                return;
            }
        };

        // Create gossipsub topic
        let encoded_topic = topics::encode_topic(&self.network_name, topic_variant);
        let topic = gossipsub::IdentTopic::new(encoded_topic.clone());

        // Publish to gossipsub
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, compressed_data)
        {
            warn!(
                "Failed to publish message to gossipsub topic {}: {:?}",
                encoded_topic, e
            );
        } else {
            debug!("Successfully published message to topic: {}", encoded_topic);
            metrics::inc_counter_vec(&*metrics::LEAN_P2P_MESSAGES_PUBLISHED_TOTAL, &[&encoded_topic]);
        }


    }

    // Bootstrap dialing/retry is handled by `PeerManager`.
}
fn peer_id_from_multiaddr(mut addr: Multiaddr) -> Option<PeerId> {
    if let Some(libp2p::multiaddr::Protocol::P2p(mh)) = addr.pop() {
        PeerId::from_multihash(mh.into()).ok()
    } else {
        None
    }
}
