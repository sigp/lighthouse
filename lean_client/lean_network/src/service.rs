use crate::config::NetworkConfig;
use futures::StreamExt;
use libp2p::{
    core::upgrade::Version,
    gossipsub, identify, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, Swarm, Transport,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(NetworkBehaviour)]
pub struct LeanBehaviour {
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

/// Messages received from the network that need to be processed
#[derive(Debug, Clone)]
pub struct NetworkMessage {
    pub topic: String,
    pub data: Vec<u8>,
}

pub struct NetworkService {
    swarm: Swarm<LeanBehaviour>,
    message_tx: Option<mpsc::UnboundedSender<NetworkMessage>>,
}

impl NetworkService {
    pub fn new(config: NetworkConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer id: {:?}", local_peer_id);

        let transport = tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&local_key)?)
            .multiplex(yamux::Config::default())
            .boxed();

        let identify = identify::Behaviour::new(identify::Config::new(
            "/lean-client/1.0.0".to_string(),
            local_key.public(),
        ));

        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        )?;

        // Configure gossipsub
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
            identify,
            mdns,
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
            message_tx: None,
        })
    }

    /// Set the message sender for forwarding network messages
    pub fn set_message_sender(&mut self, tx: mpsc::UnboundedSender<NetworkMessage>) {
        self.message_tx = Some(tx);
    }

    pub async fn start(mut self) {
        eprintln!("DEBUG: Network service start() called");
        info!("Network service started");

        loop {
            match self.swarm.select_next_some().await {
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
                            info!(
                                "Received gossipsub message from {:?} on topic {:?}",
                                propagation_source, message.topic
                            );

                            // Forward message to attestation service
                            if let Some(tx) = &self.message_tx {
                                let network_msg = NetworkMessage {
                                    topic: message.topic.to_string(),
                                    data: message.data.to_vec(),
                                };
                                if let Err(e) = tx.send(network_msg) {
                                    warn!("Failed to send network message to attestation service: {}", e);
                                }
                            }
                        }
                        LeanBehaviourEvent::Identify(event) => {
                            debug!("Identify event: {:?}", event);
                        }
                        LeanBehaviourEvent::Mdns(event) => {
                            debug!("mDNS event: {:?}", event);
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
