mod common;
use std::sync::Arc;

use common::behaviour::{CallTraceBehaviour, MockBehaviour};
use lighthouse_network::{peer_manager::PeerManagerEvent, NetworkGlobals, PeerManager};
use types::MinimalEthSpec as E;

use futures::StreamExt;
use libp2p::{
    core::either::EitherError,
    swarm::SwarmEvent,
    swarm::{protocols_handler::DummyProtocolsHandler, DummyBehaviour, KeepAlive, Swarm},
    NetworkBehaviour,
};

use slog::{debug, info};

/// Struct that mimics the lighthouse_network::Service with respect to handling peer manager
/// events.
// TODO: make this a real struct for more accurate testing.
struct Service {
    swarm: Swarm<Behaviour>,
}

impl Service {
    async fn select_next_some(&mut self) -> SwarmEvent<Ev, EitherError<void::Void, void::Void>> {
        let ev = self.swarm.select_next_some().await;
        match &ev {
            SwarmEvent::Behaviour(Ev(PeerManagerEvent::Banned(peer_id, _addr_vec))) => {
                self.swarm.ban_peer_id(*peer_id);
            }
            SwarmEvent::Behaviour(Ev(PeerManagerEvent::UnBanned(peer_id, _addr_vec))) => {
                self.swarm.unban_peer_id(*peer_id);
            }
            _ => {}
        }
        ev
    }
}

#[derive(Debug)]
struct Ev(PeerManagerEvent);
impl From<void::Void> for Ev {
    fn from(_: void::Void) -> Self {
        unreachable!("No events are emmited")
    }
}
impl From<PeerManagerEvent> for Ev {
    fn from(ev: PeerManagerEvent) -> Self {
        Ev(ev)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Ev")]
struct Behaviour {
    pm_call_trace: CallTraceBehaviour<PeerManager<E>>,
    sibling: MockBehaviour,
}

impl Behaviour {
    fn new(pm: PeerManager<E>) -> Self {
        Behaviour {
            pm_call_trace: CallTraceBehaviour::new(pm),
            sibling: MockBehaviour::new(DummyProtocolsHandler {
                // The peer manager votes No, so we make sure the combined handler stays alive this
                // way.
                keep_alive: KeepAlive::Yes,
            }),
        }
    }
}

#[tokio::test]
async fn doa() {
    let log = common::build_log(slog::Level::Debug, true);
    let globals: Arc<NetworkGlobals<E>> = Arc::new(NetworkGlobals::new_test_globals(&log));
    let pm_config = lighthouse_network::peer_manager::config::Config::default();
    let pm = PeerManager::new(pm_config, globals.clone(), &log)
        .await
        .unwrap();
    let b = Behaviour::new(pm);
    let mut pm_swarm = common::swarm::new_test_swarm(b);
    let pm_addr = common::swarm::bind_listener(&mut pm_swarm).await;
    let mut pm_service = Service { swarm: pm_swarm };
    let mut peer_swarm =
        common::swarm::new_test_swarm(DummyBehaviour::with_keep_alive(KeepAlive::Yes));
    let _peer_addr = common::swarm::bind_listener(&mut peer_swarm).await;

    // Dial
    peer_swarm.dial(pm_addr).unwrap();
    loop {
        tokio::select! {
            peer_ev = peer_swarm.select_next_some() => {
                debug!(log, "[Peer] {:?}", peer_ev);
            },
            pm_event = pm_service.select_next_some() => {
                debug!(log, "[PM] {:?}", pm_event);
            }
        }
    }
}
