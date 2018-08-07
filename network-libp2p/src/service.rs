extern crate bigint;
extern crate bytes;
extern crate futures;
extern crate libp2p_peerstore;
extern crate libp2p_floodsub;
extern crate libp2p_identify;
extern crate libp2p_core;
extern crate libp2p_mplex;
extern crate libp2p_tcp_transport;
extern crate libp2p_kad;
extern crate slog;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_timer;
extern crate tokio_stdin;

use super::state::NetworkState;
use self::bigint::U512;
use self::futures::{ Future, Stream, Poll };
use self::futures::sync::mpsc::{ 
    unbounded, UnboundedSender, UnboundedReceiver
};
use self::libp2p_core::{ AddrComponent, Endpoint, Multiaddr,
                         Transport, ConnectionUpgrade };
use self::libp2p_kad::{ KademliaUpgrade, KademliaProcessingFuture};
use self::libp2p_floodsub::{ FloodSubFuture, FloodSubUpgrade };
use self::libp2p_identify::{ IdentifyInfo, IdentifyTransport, IdentifyOutput };
use self::slog::Logger;
use std::sync::{ Arc, RwLock, Mutex };
use std::time::{ Duration, Instant };
use std::thread;
use std::ops::Deref;
use std::io::Error as IoError;
use std::collections::VecDeque;
use self::tokio_io::{ AsyncRead, AsyncWrite };
use self::bytes::Bytes;

pub use self::libp2p_floodsub::Message;

pub struct NetworkService {
    app_to_net: UnboundedSender<Vec<u8>>,
    pub bg_thread: thread::JoinHandle<()>,
    msgs: Mutex<VecDeque<Message>>,
}

impl NetworkService {
    /// Create a new network service. Spawns a new thread running tokio
    /// services. Accepts a NetworkState, which is derived from a NetworkConfig.
    /// Also accepts a logger.
    pub fn new(state: NetworkState, log: Logger) 
        -> (Self, UnboundedReceiver<Vec<u8>>)
    {
        let (input_tx, input_rx) = unbounded();     // app -> net
        let (output_tx, output_rx) = unbounded();   // net -> app
        let bg_thread = thread::spawn(move || {
            listen(state, output_tx, input_rx, log);
        });
        let msgs = Mutex::new(VecDeque::new());
        let ns = Self {
            app_to_net: input_tx,
            bg_thread,
            msgs,
        };
        (ns, output_rx)
    }

    /// Sends a message (byte vector) to the network. The present network
    /// determines which the recipients of the message.
    pub fn send(&self, msg: Vec<u8>) {
        self.app_to_net.unbounded_send(msg).expect("unable to contact network")
    }

    pub fn read_message(&mut self) 
        -> Option<Message>
    {
        let mut buf = self.msgs.lock().unwrap();
        buf.pop_front()
    }
}

fn listen(state: NetworkState,
          app_tx: UnboundedSender<Vec<u8>>,
          raw_rx: UnboundedReceiver<Vec<u8>>,
          log: Logger) 
{
    let peer_store = state.peer_store;
    let peer_id = state.peer_id;
    let listen_multiaddr = state.listen_multiaddr;
    let listened_addrs = Arc::new(RwLock::new(vec![]));
    let rx = ApplicationReciever{ inner: raw_rx };
    
    // Build a tokio core
    let mut core =  tokio_core::reactor::Core::new().expect("tokio failure.");
    // Build a base TCP libp2p transport
    let transport = libp2p_tcp_transport::TcpConfig::new(core.handle())
        .with_upgrade(libp2p_core::upgrade::PlainTextConfig)
        .with_upgrade(libp2p_mplex::BufferedMultiplexConfig::<[_; 256]>::new())
        .into_connection_reuse();

    // Build an identify transport to allow identification and negotiation
    // of layers running atop the TCP transport (e.g., kad)
    let identify_transport = {
        let listened_addrs = listened_addrs.clone();
        let listen_multiaddr = listen_multiaddr.clone();
        IdentifyTransport::new(transport.clone(), peer_store.clone())
            // Managed NAT'ed connections - ensuring the external IP
            // is stored not the internal addr.
            .map(move |out, _, _| {
                if let(Some(ref observed), ref listen_multiaddr) =
                    (out.observed_addr, listen_multiaddr) 
                {
                    if let Some(viewed_from_outside) = 
                        transport.nat_traversal(listen_multiaddr, observed) 
                    {
                        listened_addrs.write().unwrap()
                            .push(viewed_from_outside);
                    }
                }
                out.socket
            })
    };

    // Configure and build a Kademlia upgrade to be applied
    // to the base TCP transport. 
    let kad_config = libp2p_kad::KademliaConfig {
        parallelism: 3,
        record_store: (),
        peer_store: peer_store,
        local_peer_id: peer_id.clone(),
        timeout: Duration::from_secs(2)
    };
    let kad_ctl_proto = libp2p_kad::
        KademliaControllerPrototype::new(kad_config);
    let kad_upgrade = libp2p_kad::
        KademliaUpgrade::from_prototype(&kad_ctl_proto);
   
    // Build a floodsub upgrade to allow pushing topic'ed
    // messages across the network.
    let (floodsub_upgrade, floodsub_rx) = 
        FloodSubUpgrade::new(peer_id.clone());

    // Combine the Kademlia and Identify upgrades into a single
    // upgrader struct.
    let upgrade = ConnectionUpgrader {
        kad: kad_upgrade.clone(),
        floodsub: floodsub_upgrade.clone(),
        identify: libp2p_identify::IdentifyProtocolConfig,
    };
  
    // Build a Swarm to manage upgrading connections to peers.
    let swarm_listened_addrs = listened_addrs.clone();
    let swarm_peer_id = peer_id.clone();
    let (swarm_ctl, swarm_future) = libp2p_core::swarm(
        identify_transport.clone().with_upgrade(upgrade),
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

    // Start the Swarm controller listening on the local machine
    let actual_addr = swarm_ctl
        .listen_on(listen_multiaddr)
        .expect("Failed to listen on multiaddr");
    info!(log, "libp2p listening"; "listen_addr" => actual_addr.to_string());

    // Convert the kad prototype into a controller by providing it the
    // newly built swarm.
    let (kad_ctl, kad_init) = kad_ctl_proto.start(
        swarm_ctl.clone(),
        identify_transport.clone().with_upgrade(kad_upgrade.clone()));

    // Create a new floodsub controller using a specific topic
    let topic = libp2p_floodsub::TopicBuilder::new("beacon_chain").build();
    let floodsub_ctl = libp2p_floodsub::FloodSubController::new(&floodsub_upgrade);
    floodsub_ctl.subscribe(&topic);

    // Generate a tokio timer "wheel" future that sends kad FIND_NODE at
    // a routine interval.
    let kad_poll_log = log.new(o!());
    let kad_poll = {
        let polling_peer_id = peer_id.clone();
        tokio_timer::wheel()
            .build()
            .interval_at(Instant::now(), Duration::from_secs(30))
            .map_err(|_| -> IoError { unreachable!() })
            .and_then(move |()| kad_ctl.find_node(peer_id.clone()))
            .for_each(move |peers| {
                let local_hash = U512::from(polling_peer_id.hash());
                for peer in peers {
                    let peer_hash = U512::from(peer.hash());
                    let distance = 512 - (local_hash ^ peer_hash).leading_zeros();
                    info!(kad_poll_log, "Discovered peer"; 
                          "distance" => distance,
                          "peer_id" => peer.to_base58());
                    let peer_addr = AddrComponent::P2P(peer.into_bytes()).into();
                    let dial_result = swarm_ctl.dial(
                        peer_addr,
                        identify_transport.clone().with_upgrade(floodsub_upgrade.clone())
                    );
                    if let Err(err) = dial_result {
                        warn!(kad_poll_log, "Dialling {:?} failed.", err)
                    }
                }
                Ok(())
            })
    };

    // Create a future to handle message recieved from the network
    let floodsub_rx = floodsub_rx.for_each(|msg| {
        debug!(&log, "Network receive"; "msg" => format!("{:?}", msg));
        app_tx.unbounded_send(msg.data)
            .expect("Network unable to contact application.");
        Ok(())
    });

    // Create a future to handle messages recieved from the application
    let app_rx = rx.for_each(|msg| {
        debug!(&log, "Network publish"; "msg" => format!("{:?}", msg));
        floodsub_ctl.publish(&topic, msg);
        Ok(())
    });

    // Generate a full future
    let final_future = swarm_future
        .select(floodsub_rx).map_err(|(err, _)| err).map(|((), _)| ())
        .select(app_rx).map_err(|(err, _)| err).map(|((), _)| ())
        .select(kad_poll).map_err(|(err, _)| err).map(|((), _)| ())
        .select(kad_init).map_err(|(err, _)| err).and_then(|((), n)| n);

    core.run(final_future).unwrap();
}

struct ApplicationReciever {
    inner: UnboundedReceiver<Vec<u8>>,
}

impl Stream for ApplicationReciever {
    type Item = Vec<u8>;
    type Error = IoError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.inner
            .poll()
            .map_err(|_| unreachable!())
    }
}

#[derive(Clone)]
struct ConnectionUpgrader<P, R> {
    kad: KademliaUpgrade<P, R>,
    identify: libp2p_identify::IdentifyProtocolConfig,
    floodsub: FloodSubUpgrade,
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
                    .map(|upg| upg.into()),
            ),
            _ => unreachable!()
        }

    }
}

enum FinalUpgrade<C> {
    Kad(KademliaProcessingFuture),
    Identify(IdentifyOutput<C>),
    FloodSub(FloodSubFuture),
}

impl<C> From<libp2p_kad::KademliaProcessingFuture> for FinalUpgrade<C> { #[inline]
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
    fn from(upgr: FloodSubFuture) -> Self {
        FinalUpgrade::FloodSub(upgr)
    }
}
