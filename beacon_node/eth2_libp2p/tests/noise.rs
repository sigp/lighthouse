#![cfg(test)]
use crate::behaviour::Behaviour;
use crate::multiaddr::Protocol;
use ::types::{EnrForkId, MinimalEthSpec};
use eth2_libp2p::discovery::{build_enr, CombinedKey, CombinedKeyExt};
use eth2_libp2p::*;
use futures::prelude::*;
use libp2p::core::identity::Keypair;
use libp2p::{
    core,
    core::{muxing::StreamMuxerBox, transport::boxed::Boxed},
    secio,
    swarm::{SwarmBuilder, SwarmEvent},
    PeerId, Swarm, Transport,
};
use slog::{crit, debug, info, Level};
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

type TSpec = MinimalEthSpec;

mod common;

type Libp2pBehaviour = Behaviour<TSpec>;

/// Build and return a eth2_libp2p Swarm with only secio support.
fn build_secio_swarm(
    config: &NetworkConfig,
    log: slog::Logger,
) -> error::Result<Swarm<Libp2pBehaviour>> {
    let local_keypair = Keypair::generate_secp256k1();
    let local_peer_id = PeerId::from(local_keypair.public());
    let enr_key = CombinedKey::from_libp2p(&local_keypair).unwrap();

    let enr = build_enr::<TSpec>(&enr_key, config, EnrForkId::default()).unwrap();
    let network_globals = Arc::new(NetworkGlobals::new(
        enr,
        config.libp2p_port,
        config.discovery_port,
        &log,
    ));

    let mut swarm = {
        // Set up the transport - tcp/ws with secio and mplex/yamux
        let transport = build_secio_transport(local_keypair.clone());
        // Lighthouse network behaviour
        let behaviour = Behaviour::new(&local_keypair, config, network_globals.clone(), &log)?;
        // requires a tokio runtime
        struct Executor(tokio::runtime::Handle);
        impl libp2p::core::Executor for Executor {
            fn exec(&self, f: Pin<Box<dyn Future<Output = ()> + Send>>) {
                self.0.spawn(f);
            }
        }
        SwarmBuilder::new(transport, behaviour, local_peer_id.clone())
            .executor(Box::new(Executor(tokio::runtime::Handle::current())))
            .build()
    };

    // listen on the specified address
    let listen_multiaddr = {
        let mut m = Multiaddr::from(config.listen_address);
        m.push(Protocol::Tcp(config.libp2p_port));
        m
    };

    match Swarm::listen_on(&mut swarm, listen_multiaddr.clone()) {
        Ok(_) => {
            let mut log_address = listen_multiaddr;
            log_address.push(Protocol::P2p(local_peer_id.clone().into()));
            info!(log, "Listening established"; "address" => format!("{}", log_address));
        }
        Err(err) => {
            crit!(
                log,
                "Unable to listen on libp2p address";
                "error" => format!("{:?}", err),
                "listen_multiaddr" => format!("{}", listen_multiaddr),
            );
            return Err("Libp2p was unable to listen on the given listen address.".into());
        }
    };

    // helper closure for dialing peers
    let mut dial_addr = |multiaddr: &Multiaddr| {
        match Swarm::dial_addr(&mut swarm, multiaddr.clone()) {
            Ok(()) => debug!(log, "Dialing libp2p peer"; "address" => format!("{}", multiaddr)),
            Err(err) => debug!(
                log,
                "Could not connect to peer"; "address" => format!("{}", multiaddr), "error" => format!("{:?}", err)
            ),
        };
    };

    // attempt to connect to any specified boot-nodes
    for bootnode_enr in &config.boot_nodes {
        for multiaddr in &bootnode_enr.multiaddr() {
            // ignore udp multiaddr if it exists
            let components = multiaddr.iter().collect::<Vec<_>>();
            if let Protocol::Udp(_) = components[1] {
                continue;
            }
            dial_addr(multiaddr);
        }
    }
    Ok(swarm)
}

/// Build a simple TCP transport with secio, mplex/yamux.
fn build_secio_transport(local_private_key: Keypair) -> Boxed<(PeerId, StreamMuxerBox), Error> {
    let transport = libp2p_tcp::TokioTcpConfig::new().nodelay(true);
    transport
        .upgrade(core::upgrade::Version::V1)
        .authenticate(secio::SecioConfig::new(local_private_key))
        .multiplex(core::upgrade::SelectUpgrade::new(
            libp2p::yamux::Config::default(),
            libp2p::mplex::MplexConfig::new(),
        ))
        .map(|(peer, muxer), _| (peer, core::muxing::StreamMuxerBox::new(muxer)))
        .timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(20))
        .map_err(|err| Error::new(ErrorKind::Other, err))
        .boxed()
}

/// Test if the encryption falls back to secio if noise isn't available
#[tokio::test]
async fn test_secio_noise_fallback() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    let port = common::unused_port("tcp").unwrap();
    let noisy_config = common::build_config(port, vec![]);
    let (_signal, exit) = exit_future::signal();
    let executor =
        environment::TaskExecutor::new(tokio::runtime::Handle::current(), exit, log.clone());
    let mut noisy_node = Service::new(executor, &noisy_config, EnrForkId::default(), &log)
        .expect("should build a libp2p instance")
        .1;

    let port = common::unused_port("tcp").unwrap();
    let secio_config = common::build_config(port, vec![common::get_enr(&noisy_node)]);

    // Building a custom Libp2pService from outside the crate isn't possible because of
    // private fields in the Libp2pService struct. A swarm is good enough for testing
    // compatibility with secio.
    let mut secio_swarm =
        build_secio_swarm(&secio_config, log.clone()).expect("should build a secio swarm");

    let secio_log = log.clone();

    let noisy_future = async {
        loop {
            noisy_node.next_event().await;
        }
    };

    let secio_future = async {
        loop {
            match secio_swarm.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    // secio node negotiated a secio transport with
                    // the noise compatible node
                    info!(secio_log, "Connected to peer {}", peer_id);
                    return;
                }
                _ => {} // Ignore all other events
            }
        }
    };

    tokio::select! {
        _ = noisy_future => {}
        _ = secio_future => {}
        _ = tokio::time::delay_for(Duration::from_millis(800)) => {
            panic!("Future timed out");
        }
    }
}
