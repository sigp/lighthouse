mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::behaviours::{MethodCall, PuppetBehaviour, PuppetEvent};
use futures::StreamExt;
use libp2p::swarm::protocols_handler::DummyProtocolsHandler;
use libp2p::swarm::{DialPeerCondition, DummyBehaviour, SwarmEvent};
use libp2p::swarm::{NetworkBehaviourAction as NBAction, Swarm};
use libp2p::{development_transport, NetworkBehaviour, PeerId};
use lighthouse_network::{Multiaddr, NetworkGlobals};
use slog::{debug, info, o};
use tokio;

#[derive(Debug)]
struct Event(());

#[derive(NetworkBehaviour)]
#[behaviour(event_process = false, out_event = "Event")]
struct Behaviour {
    /// Behaviour used to fake other sibling behaviour's "calls" to the swarm. It also registeres
    /// calls from the swarm to the behaviour.
    pub puppet: PuppetBehaviour,
    // pub peer_manager: PeerManager<E>,
}

// Simply to make some code shorter
struct Node {
    swarm: Swarm<Behaviour>,
}
impl std::ops::Deref for Node {
    type Target = Swarm<Behaviour>;

    fn deref(&self) -> &Self::Target {
        &self.swarm
    }
}
impl std::ops::DerefMut for Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.swarm
    }
}

impl Node {
    pub fn queue_event(&mut self, ev: PuppetEvent) {
        self.swarm.behaviour_mut().puppet.queue_event(ev)
    }

    pub fn calls(&self) -> &HashMap<MethodCall, usize> {
        self.swarm.behaviour().puppet.calls()
    }

    // pub fn peer_manager(&mut self) -> &mut PeerManager<E> {
    // &mut self.swarm.behaviour_mut().peer_manager
    // }
}

impl From<()> for Event {
    fn from(_: ()) -> Self {
        unreachable!("Puppet Behaviour does not emit events")
    }
}

async fn build_swarm(log: slog::Logger) -> Node {
    let local_key = libp2p::identity::Keypair::generate_secp256k1();
    let local_peer_id = PeerId::from(local_key.public());

    // Build the swarm
    let swarm = {
        let transport = development_transport(local_key)
            .await
            .expect("builds dev transport");

        let behaviour = Behaviour {
            puppet: Default::default(),
            // peer_manager,
        };
        Swarm::new(transport, behaviour, local_peer_id)
    };
    Node { swarm }
}

async fn build_dummy_swarm() -> Swarm<DummyBehaviour> {
    let local_key = libp2p::identity::Keypair::generate_secp256k1();
    let local_peer_id = PeerId::from(local_key.public());
    let transport = development_transport(local_key)
        .await
        .expect("builds dev transport");
    let behaviour = DummyBehaviour::with_keep_alive(libp2p::swarm::KeepAlive::Yes);
    Swarm::new(transport, behaviour, local_peer_id)
}

#[tokio::test]
async fn peer_manager_dial() {
    let log = common::build_log(slog::Level::Trace, true);

    // Build the peer manager node and bind a listener
    // let (mut node, globals) =
    // build_swarm(log.new(o!("node" => "peer_manager")), Config::default()).await;
    let mut node = build_swarm(log.new(o!("node" => "puppet"))).await;
    let _our_addr = common::behaviours::bind_listener(&mut node).await;

    // Build the dummy swarm and bind a listener
    let mut dummy = build_dummy_swarm().await;
    let dummy_addr = common::behaviours::bind_listener(&mut dummy).await;

    // Dial dummy from a sibling behaviour
    node.queue_event(NBAction::DialAddress {
        address: dummy_addr,
        handler: DummyProtocolsHandler {
            keep_alive: libp2p::swarm::KeepAlive::Yes,
        },
    });
    debug!(log, "running loop");
    loop {
        tokio::select! {
            ev = node.select_next_some() => {
                debug!(log, "Swarm event"; "ev" => ?ev);
            }
            ev = dummy.select_next_some() => {
                debug!(log, "Dummy swarm event"; "ev" => ?ev);
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(20)) => {
                // TODO: No way for the behaviour to know about this change.
                debug!(log, "Method calls"; "calls" => ?node.calls());
                return;
            }

        }
    }
}
