mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::behaviours::{MethodCall, PuppetBehaviour, PuppetEvent};
use futures::StreamExt;
use libp2p::swarm::{DialPeerCondition, DummyBehaviour, SwarmEvent};
use libp2p::swarm::{NetworkBehaviourAction as NBAction, Swarm};
use libp2p::{tokio_development_transport, NetworkBehaviour, PeerId};
use lighthouse_network::{Multiaddr, NetworkGlobals};
use slog::{debug, info, o};
use tokio;
use types::MinimalEthSpec as E;

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



