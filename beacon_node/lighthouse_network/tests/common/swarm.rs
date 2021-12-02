use super::behaviour::{CallTraceBehaviour, MockBehaviour};

use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmBuilder};
use libp2p::Transport;

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
