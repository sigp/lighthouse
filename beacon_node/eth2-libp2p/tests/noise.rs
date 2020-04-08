#![cfg(test)]
use crate::behaviour::{Behaviour, BehaviourEvent};
use crate::multiaddr::Protocol;
use ::types::{EnrForkId, MinimalEthSpec};
use eth2_libp2p::discovery::build_enr;
use eth2_libp2p::*;
use futures::prelude::*;
use libp2p::core::identity::Keypair;
use libp2p::{
    core,
    core::{muxing::StreamMuxerBox, nodes::Substream, transport::boxed::Boxed},
    secio, PeerId, Swarm, Transport,
};
use slog::{crit, debug, info, Level};
use std::convert::TryInto;
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;

type TSpec = MinimalEthSpec;

mod common;

type Libp2pStream = Boxed<(PeerId, StreamMuxerBox), Error>;
type Libp2pBehaviour = Behaviour<Substream<StreamMuxerBox>, TSpec>;

/// Build and return a eth2_libp2p Swarm with only secio support.
fn build_secio_swarm(
    config: &NetworkConfig,
    log: slog::Logger,
) -> error::Result<Swarm<Libp2pStream, Libp2pBehaviour>> {
    let local_keypair = Keypair::generate_secp256k1();
    let local_peer_id = PeerId::from(local_keypair.public());
    let enr_key: libp2p::discv5::enr::CombinedKey = local_keypair.clone().try_into().unwrap();
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
        Swarm::new(transport, behaviour, local_peer_id.clone())
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
    let transport = libp2p::tcp::TcpConfig::new().nodelay(true);
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
#[test]
fn test_secio_noise_fallback() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    let noisy_config = common::build_config(56010, vec![], None);
    let mut noisy_node = Service::new(&noisy_config, EnrForkId::default(), log.clone())
        .expect("should build a libp2p instance")
        .1;

    let secio_config = common::build_config(56011, vec![common::get_enr(&noisy_node)], None);

    // Building a custom Libp2pService from outside the crate isn't possible because of
    // private fields in the Libp2pService struct. A swarm is good enough for testing
    // compatibility with secio.
    let mut secio_swarm =
        build_secio_swarm(&secio_config, log.clone()).expect("should build a secio swarm");

    let secio_log = log.clone();

    let noisy_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match noisy_node.poll().unwrap() {
                _ => return Ok(Async::NotReady),
            }
        }
    });

    let secio_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match secio_swarm.poll().unwrap() {
                Async::Ready(Some(BehaviourEvent::PeerDialed(peer_id))) => {
                    // secio node negotiated a secio transport with
                    // the noise compatible node
                    info!(secio_log, "Connected to peer {}", peer_id);
                    return Ok(Async::Ready(true));
                }
                _ => return Ok(Async::NotReady),
            }
        }
    });

    // execute the futures and check the result
    let test_result = Arc::new(AtomicBool::new(false));
    let error_result = test_result.clone();
    let thread_result = test_result.clone();
    tokio::run(
        noisy_future
            .select(secio_future)
            .timeout(Duration::from_millis(1000))
            .map_err(move |_| error_result.store(false, Relaxed))
            .map(move |result| {
                thread_result.store(result.0, Relaxed);
            }),
    );
    assert!(test_result.load(Relaxed));
}
