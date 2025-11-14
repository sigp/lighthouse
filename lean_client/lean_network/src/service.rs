use crate::config::NetworkConfig;
use futures::StreamExt;
use libp2p::{
    core::upgrade::Version,
    identify, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, Swarm, Transport,
};
use std::time::Duration;
use task_executor::TaskExecutor;
use tracing::{debug, info, warn};

#[derive(NetworkBehaviour)]
pub struct LeanBehaviour {
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

pub struct NetworkService {
    swarm: Swarm<LeanBehaviour>,
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

        let behaviour = LeanBehaviour { identify, mdns };

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

        Ok(Self { swarm })
    }

    pub fn start(mut self, executor: TaskExecutor) {
        let network_future = async move {
            info!("Network service started");

            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on: {:?}", address);
                    }
                    SwarmEvent::Behaviour(event) => {
                        debug!("Behaviour event: {:?}", event);
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
        };

        executor.spawn(network_future, "lean_network_service");
    }
}
