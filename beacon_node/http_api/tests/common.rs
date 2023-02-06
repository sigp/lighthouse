use beacon_chain::{
    test_utils::{BeaconChainHarness, BoxedMutator, EphemeralTestingSlotClockHarnessType},
    BeaconChain, BeaconChainTypes,
};
use directory::DEFAULT_ROOT_DIR;
use eth2::{BeaconNodeHttpClient, Timeouts};
use http_api::{Config, Context};
use lighthouse_network::{
    discv5::enr::{CombinedKey, EnrBuilder},
    libp2p::{
        core::connection::ConnectionId,
        swarm::{
            behaviour::{ConnectionEstablished, FromSwarm},
            NetworkBehaviour,
        },
    },
    rpc::methods::{MetaData, MetaDataV2},
    types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield, SyncState},
    ConnectedPoint, Enr, NetworkGlobals, PeerId, PeerManager,
};
use logging::test_logger;
use network::{NetworkReceivers, NetworkSenders};
use sensitive_url::SensitiveUrl;
use slog::Logger;
use slot_clock::TestingSlotClock;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use store::MemoryStore;
use tokio::sync::oneshot;
use types::{ChainSpec, EthSpec};

pub const TCP_PORT: u16 = 42;
pub const UDP_PORT: u16 = 42;
pub const SEQ_NUMBER: u64 = 0;
pub const EXTERNAL_ADDR: &str = "/ip4/0.0.0.0/tcp/9000";

/// HTTP API tester that allows interaction with the underlying beacon chain harness.
pub struct InteractiveTester<E: EthSpec> {
    pub harness: BeaconChainHarness<EphemeralTestingSlotClockHarnessType<E>>,
    pub client: BeaconNodeHttpClient,
    pub network_rx: NetworkReceivers<E>,
    _server_shutdown: oneshot::Sender<()>,
}

/// The result of calling `create_api_server`.
///
/// Glue-type between `tests::ApiTester` and `InteractiveTester`.
pub struct ApiServer<E: EthSpec, SFut: Future<Output = ()>> {
    pub server: SFut,
    pub listening_socket: SocketAddr,
    pub shutdown_tx: oneshot::Sender<()>,
    pub network_rx: NetworkReceivers<E>,
    pub local_enr: Enr,
    pub external_peer_id: PeerId,
}

type Initializer<E> = Box<
    dyn FnOnce(HarnessBuilder<EphemeralHarnessType<E>>) -> HarnessBuilder<EphemeralHarnessType<E>>,
>;
type Mutator<E> = BoxedMutator<E, MemoryStore<E>, MemoryStore<E>, TestingSlotClock>;

impl<E: EthSpec> InteractiveTester<E> {
    pub async fn new(spec: Option<ChainSpec>, validator_count: usize) -> Self {
        Self::new_with_initializer_and_mutator(spec, validator_count, None, None).await
    }

    pub async fn new_with_initializer_and_mutator(
        spec: Option<ChainSpec>,
        validator_count: usize,
        initializer: Option<Initializer<E>>,
        mutator: Option<Mutator<E>>,
    ) -> Self {
        let mut harness_builder = BeaconChainHarness::builder(E::default())
            .spec_or_default(spec)
            .logger(test_logger())
            .mock_execution_layer();

        harness_builder = if let Some(initializer) = initializer {
            // Apply custom initialization provided by the caller.
            initializer(harness_builder)
        } else {
            // Apply default initial configuration.
            harness_builder
                .deterministic_keypairs(validator_count)
                .fresh_ephemeral_store()
        };

        // Add a mutator for the beacon chain builder which will be called in
        // `HarnessBuilder::build`.
        if let Some(mutator) = mutator {
            harness_builder = harness_builder.initial_mutator(mutator);
        }

        let harness = harness_builder.build();

        let ApiServer {
            server,
            listening_socket,
            shutdown_tx: _server_shutdown,
            network_rx,
            ..
        } = create_api_server(harness.chain.clone(), harness.logger().clone()).await;

        tokio::spawn(server);

        let client = BeaconNodeHttpClient::new(
            SensitiveUrl::parse(&format!(
                "http://{}:{}",
                listening_socket.ip(),
                listening_socket.port()
            ))
            .unwrap(),
            Timeouts::set_all(Duration::from_secs(1)),
        );

        Self {
            harness,
            client,
            network_rx,
            _server_shutdown,
        }
    }
}

pub async fn create_api_server<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    log: Logger,
) -> ApiServer<T::EthSpec, impl Future<Output = ()>> {
    // Get a random unused port.
    let port = unused_port::unused_tcp_port().unwrap();
    create_api_server_on_port(chain, log, port).await
}

pub async fn create_api_server_on_port<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    log: Logger,
    port: u16,
) -> ApiServer<T::EthSpec, impl Future<Output = ()>> {
    let (network_senders, network_receivers) = NetworkSenders::new();

    // Default metadata
    let meta_data = MetaData::V2(MetaDataV2 {
        seq_number: SEQ_NUMBER,
        attnets: EnrAttestationBitfield::<T::EthSpec>::default(),
        syncnets: EnrSyncCommitteeBitfield::<T::EthSpec>::default(),
    });
    let enr_key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").build(&enr_key).unwrap();
    let network_globals = Arc::new(NetworkGlobals::new(
        enr.clone(),
        TCP_PORT,
        UDP_PORT,
        meta_data,
        vec![],
        &log,
    ));

    // Only a peer manager can add peers, so we create a dummy manager.
    let config = lighthouse_network::peer_manager::config::Config::default();
    let mut pm = PeerManager::new(config, network_globals.clone(), &log).unwrap();

    // add a peer
    let peer_id = PeerId::random();

    let endpoint = &ConnectedPoint::Listener {
        local_addr: EXTERNAL_ADDR.parse().unwrap(),
        send_back_addr: EXTERNAL_ADDR.parse().unwrap(),
    };
    let connection_id = ConnectionId::new(1);
    pm.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
        peer_id,
        connection_id,
        endpoint,
        failed_addresses: &[],
        other_established: 0,
    }));
    *network_globals.sync_state.write() = SyncState::Synced;

    let eth1_service =
        eth1::Service::new(eth1::Config::default(), log.clone(), chain.spec.clone()).unwrap();

    let context = Arc::new(Context {
        config: Config {
            enabled: true,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: port,
            allow_origin: None,
            tls_config: None,
            allow_sync_stalled: false,
            data_dir: std::path::PathBuf::from(DEFAULT_ROOT_DIR),
            spec_fork_name: None,
        },
        chain: Some(chain.clone()),
        network_senders: Some(network_senders),
        network_globals: Some(network_globals),
        eth1_service: Some(eth1_service),
        log,
    });
    let ctx = context.clone();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_shutdown = async {
        // It's not really interesting why this triggered, just that it happened.
        let _ = shutdown_rx.await;
    };
    let (listening_socket, server) = http_api::serve(ctx, server_shutdown).unwrap();

    ApiServer {
        server,
        listening_socket,
        shutdown_tx,
        network_rx: network_receivers,
        local_enr: enr,
        external_peer_id: peer_id,
    }
}
