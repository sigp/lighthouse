use crate::config::NetworkConfig;
use crate::topics::{self, Topic};
use futures::StreamExt;
use lean_consensus::attestation::SignedAttestation;
use lean_consensus::lean_block::SignedLeanBlockWithAttestation;
use libp2p::identity::{self, Keypair};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    gossipsub::{self, MessageId},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use sha2::{Digest, Sha256};
use snap::raw::{Decoder as RawDecoder, Encoder as RawEncoder};
use ssz::{Decode, Encode};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};
use types::EthSpec;

/// Domain prefix for valid snappy-compressed messages per Eth2 networking spec
/// This is prepended to message data before hashing to create unique message IDs
const MESSAGE_DOMAIN_VALID_SNAPPY: &[u8] = &[0x01, 0x00, 0x00, 0x00];

#[derive(NetworkBehaviour)]
pub struct LeanBehaviour {
    gossipsub: gossipsub::Behaviour,
}

/// Messages received from the network that need to be processed
pub enum NetworkMessage<E: EthSpec> {
    /// Signed attestation received from network
    Attestation(Arc<SignedAttestation>),
    /// Block received from network
    Block(Arc<SignedLeanBlockWithAttestation<E>>),
}

/// Bootstrap node status tracking
#[derive(Debug, Clone)]
struct BootstrapNode {
    /// The multiaddr of the bootstrap node
    multiaddr: Multiaddr,
    /// Last time we attempted to connect
    last_attempt: Option<Instant>,
    /// Number of connection attempts
    attempt_count: u32,
    /// Whether we're currently connected
    connected: bool,
}

pub struct NetworkService<E: EthSpec> {
    swarm: Swarm<LeanBehaviour>,
    network_recv: mpsc::UnboundedSender<NetworkMessage<E>>,
    network_send: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    /// Cache of bootstrap nodes with retry state
    bootstrap_nodes: VecDeque<BootstrapNode>,
    /// Interval between bootstrap node retry attempts (in seconds)
    bootstrap_retry_interval: Duration,
    /// Network name used for topic encoding
    network_name: String,
}

impl<E: EthSpec> NetworkService<E> {
    pub fn new(
        config: NetworkConfig,
        network_recv: mpsc::UnboundedSender<NetworkMessage<E>>,
        network_send: mpsc::UnboundedReceiver<NetworkMessage<E>>,
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
            .validation_mode(gossipsub::ValidationMode::None)
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
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| format!("Failed to create gossipsub behaviour: {}", e))?;

        let behaviour = LeanBehaviour { gossipsub };

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

        // Initialize bootstrap nodes cache
        let mut bootstrap_nodes = VecDeque::new();
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

            if let Some(peer_in_addr) = peer_id_from_multiaddr(multiaddr.clone()) {
                if peer_in_addr != local_peer_id {
                    bootstrap_nodes.push_back(BootstrapNode {
                        multiaddr,
                        last_attempt: None,
                        attempt_count: 0,
                        connected: false,
                    });
                }
            }
        }

        info!(
            "Initialized {} bootstrap nodes for retry",
            bootstrap_nodes.len()
        );

        Ok(Self {
            swarm,
            network_recv,
            network_send,
            bootstrap_nodes,
            bootstrap_retry_interval: Duration::from_secs(5), // Retry every 5 seconds
            network_name,
        })
    }

    /// Decode message based on topic and create appropriate NetworkMessage
    /// Messages are expected to be snappy-compressed
    fn decode_network_message(&self, topic: &str, data: &[u8]) -> Option<NetworkMessage<E>> {
        let base_topic = match topics::parse_topic_name(topic, &self.network_name) {
            Some(name) => name,
            None => {
                debug!("Unknown topic format: {}", topic);
                return None;
            }
        };

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
                    Some(NetworkMessage::Block(Arc::new(block)))
                }
                Err(e) => {
                    warn!("Failed to decode lean block: {:?}", e);
                    None
                }
            },
            Topic::Attestation => match SignedAttestation::from_ssz_bytes(&decompressed) {
                Ok(signed_attestation) => {
                    debug!("Successfully decoded signed lean attestation from network");
                    Some(NetworkMessage::Attestation(Arc::new(signed_attestation)))
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

        // Attempt initial connections to bootstrap nodes
        self.attempt_bootstrap_connections();

        loop {
            tokio::select! {
                // Retry bootstrap node connections periodically
                _ = tokio::time::sleep(self.bootstrap_retry_interval) => {
                    self.attempt_bootstrap_connections();
                }

                // Handle messages to publish
                Some(msg) = self.network_send.recv() => {
                    self.publish_message(msg).await;
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
                                self.decode_network_message(message.topic.as_str(), &message.data)
                            {
                                match &network_msg {
                                    NetworkMessage::Attestation(_) => {
                                        info!("Forwarding attestation to attestation service");
                                    }
                                    NetworkMessage::Block(_) => {
                                        info!("Forwarding block to attestation service");
                                    }
                                }

                                if let Err(e) = self.network_recv.send(network_msg) {
                                    warn!("Failed to send network message to attestation service: {}", e);
                                }
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
                    // Mark matching bootstrap nodes as connected
                    self.mark_bootstrap_node_connected_by_endpoint(&endpoint);
                }
                SwarmEvent::ConnectionClosed {
                    peer_id, cause, ..
                } => {
                    debug!("Connection closed with peer: {:?}, cause: {:?}", peer_id, cause);
                }
                SwarmEvent::IncomingConnection { .. } => {
                    debug!("Incoming connection");
                }
                SwarmEvent::IncomingConnectionError { error, .. } => {
                    warn!("Incoming connection error: {:?}", error);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    warn!("Outgoing connection error to {:?}: {:?}", peer_id, error);
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

    /// Publishes a message to the gossipsub network
    async fn publish_message(&mut self, msg: NetworkMessage<E>) {
        let (topic_variant, data) = match &msg {
            NetworkMessage::Attestation(signed_attestation) => {
                info!(
                    slot = signed_attestation.message.attestation_data.slot.0,
                    validator_id = signed_attestation.message.validator_id,
                    "Publishing attestation to network"
                );
                (Topic::Attestation, signed_attestation.as_ssz_bytes())
            }
            NetworkMessage::Block(block) => {
                info!(
                    slot = block.message.block.slot.0,
                    "Publishing block to network"
                );
                (Topic::Block, block.as_ssz_bytes())
            }
        };

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
        }
    }

    /// Attempts to connect to bootstrap nodes that are not yet connected
    fn attempt_bootstrap_connections(&mut self) {
        let now = Instant::now();
        let mut connected_count = 0;
        let mut attempted_count = 0;

        for bootstrap_node in self.bootstrap_nodes.iter_mut() {
            if bootstrap_node.connected {
                connected_count += 1;
                continue;
            }

            // Check if enough time has passed since the last attempt
            if let Some(last_attempt) = bootstrap_node.last_attempt {
                if now.duration_since(last_attempt) < self.bootstrap_retry_interval {
                    continue;
                }
            }

            // Attempt to dial the bootstrap node
            match self.swarm.dial(bootstrap_node.multiaddr.clone()) {
                Ok(_) => {
                    bootstrap_node.last_attempt = Some(now);
                    bootstrap_node.attempt_count += 1;
                    attempted_count += 1;
                    debug!(
                        "Attempting to connect to bootstrap node: {} (attempt #{})",
                        bootstrap_node.multiaddr, bootstrap_node.attempt_count
                    );
                }
                Err(e) => {
                    bootstrap_node.last_attempt = Some(now);
                    bootstrap_node.attempt_count += 1;
                    attempted_count += 1;
                    warn!(
                        "Failed to dial bootstrap node {}: {:?} (attempt #{})",
                        bootstrap_node.multiaddr, e, bootstrap_node.attempt_count
                    );
                }
            }
        }

        // Log summary
        if attempted_count > 0 {
            debug!(
                "Bootstrap node status: {}/{} connected, attempted {} new connections",
                connected_count,
                self.bootstrap_nodes.len(),
                attempted_count
            );
        }
    }

    /// Marks a bootstrap node as successfully connected based on the connection endpoint
    fn mark_bootstrap_node_connected_by_endpoint(
        &mut self,
        endpoint: &libp2p::core::ConnectedPoint,
    ) {
        // Extract the remote address from the connection endpoint
        let remote_addr = endpoint.get_remote_address();

        for bootstrap_node in self.bootstrap_nodes.iter_mut() {
            // Check if this bootstrap node's multiaddr matches the connection endpoint
            // We compare the IP and port parts
            if Self::addresses_match(&bootstrap_node.multiaddr, remote_addr) {
                if !bootstrap_node.connected {
                    bootstrap_node.connected = true;
                    info!(
                        "Bootstrap node {} marked as connected after {} attempts",
                        bootstrap_node.multiaddr, bootstrap_node.attempt_count
                    );
                }
                return;
            }
        }
    }

    /// Checks if a multiaddr matches a remote address
    fn addresses_match(multiaddr: &Multiaddr, remote_addr: &Multiaddr) -> bool {
        // Simple comparison - both multiadrs should contain the same IP and port
        let multiaddr_str = multiaddr.to_string();
        let remote_str = remote_addr.to_string();

        // Extract IP and port from both addresses for comparison
        // Format is typically /ip4/{ip}/tcp/{port} or /ip6/{ip}/tcp/{port}
        multiaddr_str.contains(
            remote_str
                .split('/')
                .find(|s| s.starts_with("ip"))
                .unwrap_or(""),
        ) && multiaddr_str.contains(
            remote_str
                .split('/')
                .find(|s| s.parse::<u16>().is_ok())
                .unwrap_or(""),
        )
    }
}
fn peer_id_from_multiaddr(mut addr: Multiaddr) -> Option<PeerId> {
    if let Some(libp2p::multiaddr::Protocol::P2p(mh)) = addr.pop() {
        PeerId::from_multihash(mh.into()).ok()
    } else {
        None
    }
}
