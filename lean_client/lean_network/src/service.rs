use crate::config::NetworkConfig;
use futures::StreamExt;
use lean_consensus::attestation::Attestation;
use lean_consensus::lean_block::SignedLeanBlockWithAttestation;
use libp2p::{
    core::upgrade::Version,
    gossipsub, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, Swarm, Transport,
};
use ssz::{Decode, Encode};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use types::EthSpec;

#[derive(NetworkBehaviour)]
pub struct LeanBehaviour {
    gossipsub: gossipsub::Behaviour,
}

#[derive(Debug, Clone)]
pub struct LeanPubSubMessage {
    pub topic: String,
    pub data: Vec<u8>,
}

/// Messages received from the network that need to be processed
pub enum NetworkMessage<E: EthSpec> {
    /// Attestation received from network
    Attestation(Arc<Attestation>),
    /// Block received from network
    Block(Arc<SignedLeanBlockWithAttestation<E>>),
}

pub struct NetworkService<E: EthSpec> {
    swarm: Swarm<LeanBehaviour>,
    network_recv: mpsc::UnboundedSender<NetworkMessage<E>>,
    network_send: mpsc::UnboundedReceiver<NetworkMessage<E>>,
}

#[derive(Clone)]
pub struct NetworkServiceHandle {
    publish_tx: mpsc::UnboundedSender<LeanPubSubMessage>,
}

impl<E: EthSpec> NetworkService<E> {
    pub fn new(
        config: NetworkConfig,
        network_recv: mpsc::UnboundedSender<NetworkMessage<E>>,
        network_send: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer id: {:?}", local_peer_id);

        let transport = tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&local_key)?)
            .multiplex(yamux::Config::default())
            .boxed();


        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| format!("Failed to build gossipsub config: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| format!("Failed to create gossipsub behaviour: {}", e))?;

        let behaviour = LeanBehaviour {
            gossipsub,
        };

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );

        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port)
            .parse()
            .map_err(|e| format!("Invalid listen address: {}", e))?;

        swarm.listen_on(listen_addr)?;

        Ok(Self {
            swarm,
            network_recv,
            network_send,
        })
    }

    /// Decode message based on topic and create appropriate NetworkMessage
    fn decode_network_message(&self, topic: &str, data: &[u8]) -> Option<NetworkMessage<E>> {
        // Topic format is typically: /eth2/{fork_digest}/{topic_name}/{encoding}
        // e.g., /eth2/4a26c58b/lean_attestation/ssz_snappy
        if topic.contains("lean_attestation") || topic.contains("attestation") {
            match Attestation::from_ssz_bytes(data) {
                Ok(attestation) => {
                    debug!("Successfully decoded lean attestation from network");
                    Some(NetworkMessage::Attestation(Arc::new(attestation)))
                }
                Err(e) => {
                    warn!("Failed to decode lean attestation: {:?}", e);
                    None
                }
            }
        } else if topic.contains("lean_block") || topic.contains("block") {
            match SignedLeanBlockWithAttestation::from_ssz_bytes(data) {
                Ok(block) => {
                    debug!("Successfully decoded lean block from network");
                    Some(NetworkMessage::Block(Arc::new(block)))
                }
                Err(e) => {
                    warn!("Failed to decode lean block: {:?}", e);
                    None
                }
            }
        } else {
            debug!("Unknown topic type: {}", topic);
            None
        }
    }

    pub async fn start(mut self) {
        info!("Network service started");

        loop {
            tokio::select! {
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
                            ..
                        }) => {
                            debug!(
                                "Received gossipsub message from {:?} on topic {:?}",
                                propagation_source, message.topic
                            );

                            // Decode the message based on topic
                            if let Some(network_msg) = self.decode_network_message(
                                &message.topic.to_string(),
                                &message.data
                            ) {
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
                        _ => {
                            debug!("Other behaviour event: {:?}", event);
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
        let (topic_name, data) = match &msg {
            NetworkMessage::Attestation(attestation) => {
                info!(
                    slot = attestation.attestation_data.slot.0,
                    validator_id = attestation.validator_id,
                    "Publishing attestation to network"
                );
                ("lean_attestation", attestation.as_ssz_bytes())
            }
            NetworkMessage::Block(block) => {
                info!(
                    slot = block.message.block.slot.0,
                    "Publishing block to network"
                );
                ("lean_block", block.as_ssz_bytes())
            }
        };

        // Create gossipsub topic
        let topic = gossipsub::IdentTopic::new(topic_name);

        // Publish to gossipsub
        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
            warn!("Failed to publish message to gossipsub: {:?}", e);
        } else {
            debug!("Successfully published message to topic: {}", topic_name);
        }
    }
}

