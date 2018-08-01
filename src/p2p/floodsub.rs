extern crate bigint;
extern crate bytes;
extern crate futures;
extern crate libp2p_peerstore;
extern crate libp2p_identify;
extern crate libp2p_core;
extern crate libp2p_mplex;
extern crate libp2p_tcp_transport;
extern crate libp2p_floodsub;
extern crate libp2p_kad;
extern crate slog;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;
extern crate tokio_stdin;

use super::state::NetworkState;
use self::bigint::U512;
use self::futures::{ Future, Stream };
use self::libp2p_core::{ AddrComponent, Endpoint, Multiaddr, Transport, ConnectionUpgrade };
use self::libp2p_floodsub::{ FloodSubUpgrade, FloodSubFuture };
use self::libp2p_kad::{ KademliaUpgrade, KademliaProcessingFuture};
use self::libp2p_identify::{ IdentifyInfo, IdentifyTransport, IdentifyOutput };
use self::slog::Logger;
use std::sync::{ Arc, RwLock };
use std::time::{ Duration, Instant };
use std::ops::Deref;
use std::io::Error as IoError;
use self::tokio_io::{ AsyncRead, AsyncWrite };
use self::bytes::Bytes;

pub fn listen(state: NetworkState, log: &Logger) 
{
    let peer_store = state.peer_store;
    let peer_id = state.peer_id;
    let listen_multiaddr = state.listen_multiaddr;

    info!(log, "Local PeerId: {:?}", peer_id);
    
    let mut core =  tokio_core::reactor::Core::new().expect("tokio failure.");
    let listened_addrs = Arc::new(RwLock::new(vec![]));
    let transport = libp2p_tcp_transport::TcpConfig::new(core.handle())
        .with_upgrade(libp2p_core::upgrade::PlainTextConfig)
        .with_upgrade(libp2p_mplex::BufferedMultiplexConfig::<[_; 256]>::new())
        .into_connection_reuse();
    
    let (floodsub_upgrade, floodsub_rx) = FloodSubUpgrade::new(peer_id.clone());

    let transport_sockets = {
        let listened_addrs = listened_addrs.clone();
        let listen_multiaddr = listen_multiaddr.clone();
        IdentifyTransport::new(transport.clone(), peer_store.clone())
            .map(move |out, _, _| {
                if let(Some(ref observed), ref listen_multiaddr) = (out.observed_addr, listen_multiaddr) {
                    if let Some(viewed_from_outside) = transport.nat_traversal(listen_multiaddr, observed) {
                        listened_addrs.write().unwrap().push(viewed_from_outside);
                    }
                }
                out.socket
            })
    };

    let kad_config = libp2p_kad::KademliaConfig {
        parallelism: 3,
        record_store: (),
        peer_store: peer_store,
        local_peer_id: peer_id.clone(),
        timeout: Duration::from_secs(2)
    };

    let kad_ctl_proto = libp2p_kad::KademliaControllerPrototype::new(kad_config);
    let kad_upgrade = libp2p_kad::KademliaUpgrade::from_prototype(&kad_ctl_proto);

    let upgrade = ConnectionUpgrader {
        kad: kad_upgrade.clone(),
        identify: libp2p_identify::IdentifyProtocolConfig,
        floodsub: floodsub_upgrade.clone(),
    };
   
    let swarm_listened_addrs = listened_addrs.clone();
    let swarm_peer_id = peer_id.clone();
    let (swarm_ctl, swarm_future) = libp2p_core::swarm(
        transport_sockets.clone().with_upgrade(upgrade),
        move |upgrade, client_addr| match upgrade {
            FinalUpgrade::Kad(kad) => Box::new(kad) as Box<_>,
            FinalUpgrade::FloodSub(future) => Box::new(future) as Box<_>,
            FinalUpgrade::Identify(IdentifyOutput::Sender { sender, .. }) => sender.send(
                IdentifyInfo {
                    public_key: swarm_peer_id.clone().into_bytes(),
                    agent_version: "lighthouse/1.0.0".to_owned(),
                    protocol_version: "rust-libp2p/1.0.0".to_owned(),
                    listen_addrs: swarm_listened_addrs.read().unwrap().to_vec(),
                    protocols: vec![
                        "/ipfs/kad/1.0.0".to_owned(),
                        "/ipfs/id/1.0.0".to_owned(),
                        "/floodsub/1.0.0".to_owned(),
                    ]
                },
                &client_addr
            ),
            FinalUpgrade::Identify(IdentifyOutput::RemoteInfo { .. }) => {
                unreachable!("Never dial with the identify protocol.")
            }
        },
    );

    let actual_addr = swarm_ctl
        .listen_on(listen_multiaddr)
        .expect("Failed to listen on multiaddr");

    info!(log, "Listening on: {:?}", actual_addr);

    let (kad_ctl, kad_init) = kad_ctl_proto.start(
        swarm_ctl.clone(),
        transport_sockets.clone().with_upgrade(kad_upgrade));

    let topic = libp2p_floodsub::TopicBuilder::new("lighthouse").build();

    let floodsub_ctl = libp2p_floodsub::FloodSubController::
        new(&floodsub_upgrade);

    floodsub_ctl.subscribe(&topic);

    let floodsub_rx = floodsub_rx.for_each(|msg| {
        if let Ok(msg) = String::from_utf8(msg.data) {
            info!(log, "< {}", msg);
        }
        Ok(())
    });

    let kad_poll = {
        let polling_peer_id = peer_id.clone();
        tokio_timer::wheel()
            .build()
            .interval_at(Instant::now(), Duration::from_secs(30))
            .map_err(|_| -> IoError { unreachable!() })
            .and_then(move |()| kad_ctl.find_node(peer_id.clone()))
            .for_each(move |peers| {
                let local_hash = U512::from(polling_peer_id.hash());
                info!(log, "Peer discovery results:");
                for peer in peers {
                    let peer_hash = U512::from(peer.hash());
                    let distance = 512 - (local_hash ^ peer_hash).leading_zeros();
                    let peer_addr = AddrComponent::P2P(peer.into_bytes()).into();
                    let dial_result = swarm_ctl.dial(
                        peer_addr,
                        transport_sockets.clone().with_upgrade(
                            floodsub_upgrade.clone()
                        )
                    );
                    if let Err(err) = dial_result {
                        warn!(log, "Dialling {:?} failed.", err)
                    }
                }
                Ok(())
            })
    };

    let stdin = build_stdin_future().for_each(move |msg| {
        info!(log, "> {}", msg);
        floodsub_ctl.publish(&topic, msg.into_bytes());
        Ok(())
    });

    let final_future = swarm_future
        .select(floodsub_rx)
        .map_err(|(err, _)| err)
        .map(|((), _)| ())
        .select(stdin)
        .map_err(|(err, _)| err)
        .map(|((), _)| ())
        .select(kad_poll)
        .map_err(|(err, _)| err)
        .map(|((), _)| ())
        .select(kad_init)
        .map_err(|(err, _)| err)
        .and_then(|((), n)| n);

    core.run(final_future).unwrap();
}

fn build_stdin_future() -> impl Stream<Item = String, Error = IoError> {
    use std::mem;

    let mut buffer = Vec::new();
    tokio_stdin::spawn_stdin_stream_unbounded()
        .map_err(|_| -> IoError { panic!() })
        .filter_map(move |msg| {
            if msg != b'\r' && msg != b'\n' {
                buffer.push(msg);
                return None;
            } else if buffer.is_empty() {
                return None;
            }

            Some(String::from_utf8(mem::replace(&mut buffer, Vec::new())).unwrap())
        })
}

#[derive(Clone)]
struct ConnectionUpgrader<P, R> {
    kad: KademliaUpgrade<P, R>,
    identify: libp2p_identify::IdentifyProtocolConfig,
    floodsub: FloodSubUpgrade
}

impl<C, P, R, Pc> ConnectionUpgrade<C> for ConnectionUpgrader<P, R>
where 
    C: AsyncRead + AsyncWrite + 'static,
    P: Deref<Target = Pc> + Clone + 'static,
    for<'r> &'r Pc: libp2p_peerstore::Peerstore,
    R: 'static
{
    type NamesIter = ::std::vec::IntoIter<(Bytes, usize)>;
    type UpgradeIdentifier = usize;
    type Output = FinalUpgrade<C>;
    type Future = Box<Future<Item = FinalUpgrade<C>, Error = IoError>>;

    #[inline] 
    fn protocol_names(&self) -> Self::NamesIter {
        vec![
            (Bytes::from("/ipfs/kad/1.0.0"), 0),
            (Bytes::from("/ipfs/id/1.0.0"), 1),
            (Bytes::from("/floodsub/1.0.0"), 2),
        ].into_iter()
    }

    fn upgrade(
        self,
        socket: C,
        id: Self::UpgradeIdentifier,
        ty: Endpoint,
        remote_addr: &Multiaddr)
        -> Self::Future
    {
        match id {
            0 => Box::new(
                self.kad
                    .upgrade(socket, (), ty, remote_addr)
                    .map(|upg| upg.into())),
            1 => Box::new(
                self.identify
                    .upgrade(socket, (), ty, remote_addr)
                    .map(|upg| upg.into())),
            2 => Box::new(
                self.floodsub
                    .upgrade(socket, (), ty, remote_addr)
                    .map(|upg| upg.into())),
            _ => unreachable!()
        }

    }
}

enum FinalUpgrade<C> {
    Kad(KademliaProcessingFuture),
    Identify(IdentifyOutput<C>),
    FloodSub(FloodSubFuture),
}

impl<C> From<libp2p_kad::KademliaProcessingFuture> for FinalUpgrade<C> {
    #[inline]
    fn from(upgrade: libp2p_kad::KademliaProcessingFuture) -> Self {
        FinalUpgrade::Kad(upgrade)
    }
}

impl<C> From<IdentifyOutput<C>> for FinalUpgrade<C> {
    #[inline]
    fn from(upgrade: IdentifyOutput<C>) -> Self {
        FinalUpgrade::Identify(upgrade)
    }
}

impl<C> From<FloodSubFuture> for FinalUpgrade<C> {
    #[inline]
    fn from(upgrade: FloodSubFuture) -> Self {
        FinalUpgrade::FloodSub(upgrade)
    }
}
