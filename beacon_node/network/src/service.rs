use crate::error;
use crate::message_handler::{HandlerMessage, MessageHandler};
use crate::persisted_dht::{PersistedDht, DHT_DB_KEY};
use crate::NetworkConfig;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use core::marker::PhantomData;
use eth2_libp2p::Service as LibP2PService;
use eth2_libp2p::{rpc::RPCRequest, Enr, Libp2pEvent, MessageId, Multiaddr, PeerId, Swarm, Topic};
use eth2_libp2p::{PubsubMessage, RPCEvent};
use futures::prelude::*;
use futures::Stream;
use parking_lot::Mutex;
use slog::{debug, error, info, trace};
use std::sync::Arc;
use store::Store;
use tokio::runtime::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use types::Hash256;

/// The time in seconds that a peer will be banned and prevented from reconnecting.
const BAN_PEER_TIMEOUT: u64 = 30;

/// Service that handles communication between internal services and the eth2_libp2p network service.
pub struct Service<T: BeaconChainTypes> {
    libp2p_service: Arc<Mutex<LibP2PService>>,
    libp2p_port: u16,
    store: Arc<T::Store>,
    log: slog::Logger,
    _libp2p_exit: oneshot::Sender<()>,
    _network_send: mpsc::UnboundedSender<NetworkMessage>,
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes> Service<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        executor: &TaskExecutor,
        network_log: slog::Logger,
    ) -> error::Result<(Arc<Self>, mpsc::UnboundedSender<NetworkMessage>)> {
        // build the network channel
        let (network_send, network_recv) = mpsc::unbounded_channel::<NetworkMessage>();
        // Get a reference to the beacon chain store
        let store = beacon_chain.store.clone();
        // launch message handler thread
        let message_handler_send = MessageHandler::spawn(
            beacon_chain,
            network_send.clone(),
            executor,
            network_log.clone(),
        )?;

        // launch libp2p service
        let libp2p_service = Arc::new(Mutex::new(LibP2PService::new(
            config.clone(),
            network_log.clone(),
        )?));

        // Load DHT from store
        let key = Hash256::from_slice(&DHT_DB_KEY.as_bytes());
        let enrs: Vec<Enr> = match store.get(&key) {
            Ok(Some(p)) => {
                let p: PersistedDht = p;
                p.enrs
            }
            _ => Vec::new(),
        };
        for enr in enrs {
            libp2p_service.lock().swarm.add_enr(enr);
        }

        let libp2p_exit = spawn_service(
            libp2p_service.clone(),
            network_recv,
            message_handler_send,
            executor,
            network_log.clone(),
            config.propagation_percentage,
        )?;
        let network_service = Service {
            libp2p_service,
            libp2p_port: config.libp2p_port,
            store,
            log: network_log,
            _libp2p_exit: libp2p_exit,
            _network_send: network_send.clone(),
            _phantom: PhantomData,
        };

        Ok((Arc::new(network_service), network_send))
    }

    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Enr {
        self.libp2p_service
            .lock()
            .swarm
            .discovery()
            .local_enr()
            .clone()
    }

    /// Returns the local libp2p PeerID.
    pub fn local_peer_id(&self) -> PeerId {
        self.libp2p_service.lock().local_peer_id.clone()
    }

    /// Returns the list of `Multiaddr` that the underlying libp2p instance is listening on.
    pub fn listen_multiaddrs(&self) -> Vec<Multiaddr> {
        Swarm::listeners(&self.libp2p_service.lock().swarm)
            .cloned()
            .collect()
    }

    /// Returns the libp2p port that this node has been configured to listen using.
    pub fn listen_port(&self) -> u16 {
        self.libp2p_port
    }

    /// Returns the number of libp2p connected peers.
    pub fn connected_peers(&self) -> usize {
        self.libp2p_service.lock().swarm.connected_peers()
    }

    /// Returns the set of `PeerId` that are connected via libp2p.
    pub fn connected_peer_set(&self) -> Vec<PeerId> {
        self.libp2p_service
            .lock()
            .swarm
            .discovery()
            .connected_peer_set()
            .iter()
            .cloned()
            .collect()
    }

    /// Provides a reference to the underlying libp2p service.
    pub fn libp2p_service(&self) -> Arc<Mutex<LibP2PService>> {
        self.libp2p_service.clone()
    }

    /// Attempt to persist the enrs in the DHT to `self.store`.
    pub fn persist_dht(&self) -> Result<(), store::Error> {
        let enrs: Vec<Enr> = self
            .libp2p_service()
            .lock()
            .swarm
            .enr_entries()
            .map(|x| x.clone())
            .collect();
        info!(
            self.log,
            "Persisting DHT to store";
            "Number of peers" => format!("{}", enrs.len()),
        );
        let key = Hash256::from_slice(&DHT_DB_KEY.as_bytes());
        self.store.put(&key, &PersistedDht { enrs })?;
        Ok(())
    }
}

fn spawn_service(
    libp2p_service: Arc<Mutex<LibP2PService>>,
    network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
    message_handler_send: mpsc::UnboundedSender<HandlerMessage>,
    executor: &TaskExecutor,
    log: slog::Logger,
    propagation_percentage: Option<u8>,
) -> error::Result<tokio::sync::oneshot::Sender<()>> {
    let (network_exit, exit_rx) = tokio::sync::oneshot::channel();

    // spawn on the current executor
    executor.spawn(
        network_service(
            libp2p_service,
            network_recv,
            message_handler_send,
            log.clone(),
            propagation_percentage,
        )
        // allow for manual termination
        .select(exit_rx.then(|_| Ok(())))
        .then(move |_| {
            info!(log.clone(), "Network service shutdown");
            Ok(())
        }),
    );

    Ok(network_exit)
}

//TODO: Potentially handle channel errors
fn network_service(
    libp2p_service: Arc<Mutex<LibP2PService>>,
    mut network_recv: mpsc::UnboundedReceiver<NetworkMessage>,
    mut message_handler_send: mpsc::UnboundedSender<HandlerMessage>,
    log: slog::Logger,
    propagation_percentage: Option<u8>,
) -> impl futures::Future<Item = (), Error = eth2_libp2p::error::Error> {
    futures::future::poll_fn(move || -> Result<_, eth2_libp2p::error::Error> {
        // processes the network channel before processing the libp2p swarm
        loop {
            // poll the network channel
            match network_recv.poll() {
                Ok(Async::Ready(Some(message))) => match message {
                    NetworkMessage::RPC(peer_id, rpc_event) => {
                        trace!(log, "Sending RPC"; "rpc" => format!("{}", rpc_event));
                        libp2p_service.lock().swarm.send_rpc(peer_id, rpc_event);
                    }
                    NetworkMessage::Propagate {
                        propagation_source,
                        message_id,
                    } => {
                        // TODO: Remove this for mainnet
                        // randomly prevents propagation
                        let mut should_send = true;
                        if let Some(percentage) = propagation_percentage {
                            // not exact percentage but close enough
                            let rand = rand::random::<u8>() % 100;
                            if rand > percentage {
                                // don't propagate
                                should_send = false;
                            }
                        }
                        if !should_send {
                            info!(log, "Random filter did not propagate message");
                        } else {
                            trace!(log, "Propagating gossipsub message";
                            "propagation_peer" => format!("{:?}", propagation_source),
                            "message_id" => message_id.to_string(),
                            );
                            libp2p_service
                                .lock()
                                .swarm
                                .propagate_message(&propagation_source, message_id);
                        }
                    }
                    NetworkMessage::Publish { topics, message } => {
                        // TODO: Remove this for mainnet
                        // randomly prevents propagation
                        let mut should_send = true;
                        if let Some(percentage) = propagation_percentage {
                            // not exact percentage but close enough
                            let rand = rand::random::<u8>() % 100;
                            if rand > percentage {
                                // don't propagate
                                should_send = false;
                            }
                        }
                        if !should_send {
                            info!(log, "Random filter did not publish message");
                        } else {
                            debug!(log, "Sending pubsub message"; "topics" => format!("{:?}",topics));
                            libp2p_service.lock().swarm.publish(&topics, message);
                        }
                    }
                    NetworkMessage::Disconnect { peer_id } => {
                        libp2p_service.lock().disconnect_and_ban_peer(
                            peer_id,
                            std::time::Duration::from_secs(BAN_PEER_TIMEOUT),
                        );
                    }
                },
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => {
                    return Err(eth2_libp2p::error::Error::from("Network channel closed"));
                }
                Err(_) => {
                    return Err(eth2_libp2p::error::Error::from("Network channel error"));
                }
            }
        }

        // poll the swarm
        let mut peers_to_ban = Vec::new();
        loop {
            match libp2p_service.lock().poll() {
                Ok(Async::Ready(Some(event))) => match event {
                    Libp2pEvent::RPC(peer_id, rpc_event) => {
                        // trace!(log, "Received RPC"; "rpc" => format!("{}", rpc_event));

                        // if we received a Goodbye message, drop and ban the peer
                        if let RPCEvent::Request(_, RPCRequest::Goodbye(_)) = rpc_event {
                            peers_to_ban.push(peer_id.clone());
                        };
                        message_handler_send
                            .try_send(HandlerMessage::RPC(peer_id, rpc_event))
                            .map_err(|_| "Failed to send RPC to handler")?;
                    }
                    Libp2pEvent::PeerDialed(peer_id) => {
                        debug!(log, "Peer Dialed"; "peer_id" => format!("{:?}", peer_id));
                        message_handler_send
                            .try_send(HandlerMessage::PeerDialed(peer_id))
                            .map_err(|_| "Failed to send PeerDialed to handler")?;
                    }
                    Libp2pEvent::PeerDisconnected(peer_id) => {
                        debug!(log, "Peer Disconnected";  "peer_id" => format!("{:?}", peer_id));
                        message_handler_send
                            .try_send(HandlerMessage::PeerDisconnected(peer_id))
                            .map_err(|_| "Failed to send PeerDisconnected to handler")?;
                    }
                    Libp2pEvent::PubsubMessage {
                        id,
                        source,
                        message,
                        ..
                    } => {
                        message_handler_send
                            .try_send(HandlerMessage::PubsubMessage(id, source, message))
                            .map_err(|_| "Failed to send pubsub message to handler")?;
                    }
                    Libp2pEvent::PeerSubscribed(_, _) => {}
                },
                Ok(Async::Ready(None)) => unreachable!("Stream never ends"),
                Ok(Async::NotReady) => break,
                Err(_) => break,
            }
        }

        // ban and disconnect any peers that sent Goodbye requests
        while let Some(peer_id) = peers_to_ban.pop() {
            libp2p_service.lock().disconnect_and_ban_peer(
                peer_id.clone(),
                std::time::Duration::from_secs(BAN_PEER_TIMEOUT),
            );
        }

        Ok(Async::NotReady)
    })
}

/// Types of messages that the network service can receive.
#[derive(Debug)]
pub enum NetworkMessage {
    /// Send an RPC message to the libp2p service.
    RPC(PeerId, RPCEvent),
    /// Publish a message to gossipsub.
    Publish {
        topics: Vec<Topic>,
        message: PubsubMessage,
    },
    /// Propagate a received gossipsub message.
    Propagate {
        propagation_source: PeerId,
        message_id: MessageId,
    },
    /// Disconnect and bans a peer id.
    Disconnect { peer_id: PeerId },
}

impl<T: BeaconChainTypes> Drop for Service<T> {
    fn drop(&mut self) {
        if let Err(e) = self.persist_dht() {
            error!(
                self.log,
                "Failed to persist DHT on drop";
                "error" => format!("{:?}", e)
            )
        } else {
            info!(
                self.log,
                "Saved DHT state";
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::builder::BeaconChainBuilder;
    use eth2_libp2p::Enr;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use slog::Logger;
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::str::FromStr;
    use store::{migrate::NullMigrator, SimpleDiskStore};
    use tokio::runtime::Runtime;
    use types::{EthSpec, MinimalEthSpec};

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    #[test]
    fn test_dht_persistence() {
        // Create new LevelDB store
        let path = "/tmp";
        let store = Arc::new(SimpleDiskStore::open(&std::path::PathBuf::from(path)).unwrap());
        // Create a `BeaconChain` object to pass to `Service`
        let validator_count = 8;
        let genesis_time = 13371337;

        let log = get_logger();
        let spec = MinimalEthSpec::default_spec();

        let genesis_state = interop_genesis_state(
            &generate_deterministic_keypairs(validator_count),
            genesis_time,
            &spec,
        )
        .expect("should create interop genesis state");
        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(store)
            .store_migrator(NullMigrator)
            .genesis_state(genesis_state)
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build the dummy eth1 backend")
            .null_event_handler()
            .testing_slot_clock(std::time::Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
            .build()
            .expect("should build");
        let beacon_chain = Arc::new(chain);
        let enr1 = Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap();
        let enr2 = Enr::from_str("enr:-IS4QJ2d11eu6dC7E7LoXeLMgMP3kom1u3SE8esFSWvaHoo0dP1jg8O3-nx9ht-EO3CmG7L6OkHcMmoIh00IYWB92QABgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQIB_c-jQMOXsbjWkbN-Oj99H57gfId5pfb4wa1qxwV4CIN1ZHCCIyk").unwrap();
        let enrs = vec![enr1, enr2];

        let runtime = Runtime::new().unwrap();

        // Create new network service
        let (service, _) = Service::new(
            beacon_chain.clone(),
            &NetworkConfig::default(),
            &runtime.executor(),
            log.clone(),
        )
        .unwrap();

        // Add enrs manually to dht
        for enr in enrs.iter() {
            service.libp2p_service().lock().swarm.add_enr(enr.clone());
        }
        assert_eq!(
            enrs.len(),
            service
                .libp2p_service()
                .lock()
                .swarm
                .enr_entries()
                .collect::<Vec<_>>()
                .len(),
            "DHT should have 2 enrs"
        );
        // Drop the service value
        std::mem::drop(service);

        // Recover the network service from beacon chain store and fresh network config
        let (recovered_service, _) = Service::new(
            beacon_chain,
            &NetworkConfig::default(),
            &runtime.executor(),
            log.clone(),
        )
        .unwrap();
        assert_eq!(
            enrs.len(),
            recovered_service
                .libp2p_service()
                .lock()
                .swarm
                .enr_entries()
                .collect::<Vec<_>>()
                .len(),
            "Recovered DHT should have 2 enrs"
        );
    }
}
