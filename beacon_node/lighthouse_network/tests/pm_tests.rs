#![cfg(not(debug_assertions))]

mod common;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use common::{
    behaviour::{CallTraceBehaviour, MockBehaviour},
    swarm,
};
use lighthouse_network::{
    peer_manager::{config::Config, PeerManagerEvent},
    NetworkGlobals, PeerAction, PeerInfo, PeerManager, ReportSource,
};
use types::MinimalEthSpec as E;

use futures::StreamExt;
use libp2p::{
    core::either::EitherError,
    swarm::SwarmEvent,
    swarm::{handler::DummyConnectionHandler, DummyBehaviour, KeepAlive, Swarm},
    NetworkBehaviour,
};

use slog::debug;

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
            SwarmEvent::Behaviour(Ev(PeerManagerEvent::DisconnectPeer(peer_id, _reason))) => {
                // directly disconnect here.
                let _ = self.swarm.disconnect_peer_id(*peer_id);
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
            sibling: MockBehaviour::new(DummyConnectionHandler {
                // The peer manager votes No, so we make sure the combined handler stays alive this
                // way.
                keep_alive: KeepAlive::Yes,
            }),
        }
    }
}

#[tokio::test]
async fn banned_peers_consistency() {
    let log = common::build_log(slog::Level::Debug, false);
    let pm_log = log.new(slog::o!("who" => "[PM]"));
    let globals: Arc<NetworkGlobals<E>> = Arc::new(NetworkGlobals::new_test_globals(&log));

    // Build the peer manager.
    let (mut pm_service, pm_addr) = {
        let pm_config = Config {
            discovery_enabled: false,
            ..Default::default()
        };
        let pm = PeerManager::new(pm_config, globals.clone(), &pm_log).unwrap();
        let mut pm_swarm = swarm::new_test_swarm(Behaviour::new(pm));
        let pm_addr = swarm::bind_listener(&mut pm_swarm).await;
        let service = Service { swarm: pm_swarm };
        (service, pm_addr)
    };

    let excess_banned_peers = 15;
    let peers_to_ban =
        lighthouse_network::peer_manager::peerdb::MAX_BANNED_PEERS + excess_banned_peers;

    // Build all the dummy peers needed.
    let (mut swarm_pool, peers) = {
        let mut pool = swarm::SwarmPool::with_capacity(peers_to_ban);
        let mut peers = HashSet::with_capacity(peers_to_ban);
        for _ in 0..peers_to_ban {
            let mut peer_swarm =
                swarm::new_test_swarm(DummyBehaviour::with_keep_alive(KeepAlive::Yes));
            let _peer_addr = swarm::bind_listener(&mut peer_swarm).await;
            // It is ok to dial all at the same time since the swarm handles an event at a time.
            peer_swarm.dial(pm_addr.clone()).unwrap();
            let peer_id = pool.insert(peer_swarm);
            peers.insert(peer_id);
        }
        (pool, peers)
    };

    // we track banned peers at the swarm level here since there is no access to that info.
    let mut swarm_banned_peers = HashMap::with_capacity(peers_to_ban);
    let mut peers_unbanned = 0;
    let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(30));
    futures::pin_mut!(timeout);

    loop {
        // poll the pm and dummy swarms.
        tokio::select! {
            pm_event = pm_service.select_next_some() => {
                debug!(log, "[PM] {:?}", pm_event);
                match pm_event {
                    SwarmEvent::Behaviour(Ev(ev)) => match ev {
                        PeerManagerEvent::Banned(peer_id, _) => {
                            let has_been_unbanned = false;
                            swarm_banned_peers.insert(peer_id, has_been_unbanned);
                        }
                        PeerManagerEvent::UnBanned(peer_id, _) => {
                            *swarm_banned_peers.get_mut(&peer_id).expect("Unbanned peer must be banned first") = true;
                            peers_unbanned += 1;
                        }
                        _ => {}
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint: _,
                        num_established: _,
                        concurrent_dial_errors: _,
                    } => {
                        assert!(peers.contains(&peer_id));
                        // now we report the peer as banned.
                        pm_service
                            .swarm
                            .behaviour_mut()
                            .pm_call_trace
                            .inner()
                            .report_peer(
                                &peer_id,
                                PeerAction::Fatal,
                                ReportSource::Processor,
                                None,
                                ""
                            );
                    },
                    _ => {}
                }
            }
            Some((_peer_id, _peer_ev)) = swarm_pool.next() => {
                // we need to poll the swarms to keep the peers going
            }
            _ = timeout.as_mut() => {
                panic!("Test timeout.")
            }
        }

        if peers_unbanned == excess_banned_peers {
            let pdb = globals.peers.read();
            let inconsistencies = swarm_banned_peers
                .into_iter()
                .map(|(peer_id, was_unbanned)| {
                    was_unbanned
                        != pdb.peer_info(&peer_id).map_or(
                            false, /* We forgot about a banned peer */
                            PeerInfo::is_banned,
                        )
                });
            assert_eq!(
                inconsistencies
                    .filter(|is_consistent| *is_consistent)
                    .count(),
                peers_to_ban
            );
            return;
        }
    }
}
