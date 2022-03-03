use std::collections::HashMap;
use std::pin::Pin;

use super::behaviour::{CallTraceBehaviour, MockBehaviour};

use futures::stream::Stream;
use futures::task::{Context, Poll};
use libp2p::swarm::handler::ConnectionHandler;
use libp2p::swarm::{IntoConnectionHandler, NetworkBehaviour, Swarm, SwarmBuilder, SwarmEvent};
use libp2p::{PeerId, Transport};

use futures::StreamExt;

pub fn new_test_swarm<B>(behaviour: B) -> Swarm<B>
where
    B: NetworkBehaviour,
{
    let id_keys = libp2p::identity::Keypair::generate_ed25519();
    let local_public_key = id_keys.public();
    let transport = libp2p::core::transport::MemoryTransport::default()
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(libp2p::plaintext::PlainText2Config {
            local_public_key: local_public_key.clone(),
        })
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();
    SwarmBuilder::new(transport, behaviour, local_public_key.into()).build()
}

pub fn random_multiaddr() -> libp2p::multiaddr::Multiaddr {
    libp2p::multiaddr::Protocol::Memory(rand::random::<u64>()).into()
}

/// Bind a memory multiaddr to a compatible swarm.
pub async fn bind_listener<B: NetworkBehaviour>(
    swarm: &mut Swarm<B>,
) -> libp2p::multiaddr::Multiaddr {
    swarm.listen_on(random_multiaddr()).unwrap();
    match swarm.select_next_some().await {
        SwarmEvent::NewListenAddr {
            listener_id: _,
            address,
        } => address,
        _ => panic!("Testing swarm's first event should be a new listener"),
    }
}

#[derive(Default)]
pub struct SwarmPool<B: NetworkBehaviour> {
    swarms: HashMap<PeerId, Swarm<B>>,
}

impl<B: NetworkBehaviour> SwarmPool<B> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            swarms: HashMap::with_capacity(capacity),
        }
    }
    pub fn insert(&mut self, swarm: Swarm<B>) -> PeerId {
        let peer_id = *swarm.local_peer_id();
        self.swarms.insert(peer_id, swarm);
        peer_id
    }

    pub fn remove(&mut self, peer_id: &PeerId) {
        self.swarms.remove(peer_id);
    }

    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut Swarm<B>> {
        self.swarms.get_mut(peer_id)
    }

    pub fn swarms(&self) -> &HashMap<PeerId, Swarm<B>> {
        &self.swarms
    }

    pub fn swarms_mut(&mut self) -> &mut HashMap<PeerId, Swarm<B>> {
        &mut self.swarms
    }
}

impl<B> Stream for SwarmPool<B>
where
    B: NetworkBehaviour,
    <B as NetworkBehaviour>::ConnectionHandler: ConnectionHandler,
{
    type Item = (PeerId,
                 SwarmEvent<<B as NetworkBehaviour>::OutEvent, <<<B as NetworkBehaviour>::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::Error>);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut polls = self
            .get_mut()
            .swarms
            .iter_mut()
            .map(|(&peer_id, swarm)| swarm.map(move |ev| (peer_id, ev)))
            .collect::<futures::stream::SelectAll<_>>();
        polls.poll_next_unpin(cx)
    }
}
