use crate::{Config, Context};
use beacon_chain::{
    test_utils::{BeaconChainHarness, BoxedMutator, Builder, EphemeralHarnessType},
    BeaconChain, BeaconChainTypes,
};
use beacon_processor::{
    BeaconProcessor, BeaconProcessorChannels, BeaconProcessorConfig, BeaconProcessorQueueLengths,
};
use directory::DEFAULT_ROOT_DIR;
use eth2::{BeaconNodeHttpClient, Timeouts};
use lighthouse_network::{
    discv5::enr::CombinedKey,
    libp2p::swarm::{
        behaviour::{ConnectionEstablished, FromSwarm},
        ConnectionId, NetworkBehaviour,
    },
    rpc::methods::{MetaData, MetaDataV2},
    types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield, SyncState},
    ConnectedPoint, Enr, NetworkGlobals, PeerId, PeerManager,
};
use logging::test_logger;
use network::{NetworkReceivers, NetworkSenders};
use sensitive_url::SensitiveUrl;
use slog::Logger;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use store::MemoryStore;
use task_executor::test_utils::TestRuntime;
use types::{ChainSpec, EthSpec};

pub const TCP_PORT: u16 = 42;
pub const UDP_PORT: u16 = 42;
pub const SEQ_NUMBER: u64 = 0;
pub const EXTERNAL_ADDR: &str = "/ip4/0.0.0.0/tcp/9000";

/// HTTP API tester that allows interaction with the underlying beacon chain harness.
pub struct InteractiveTester<E: EthSpec> {
    pub ctx: Arc<Context<EphemeralHarnessType<E>>>,
    pub harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    pub client: BeaconNodeHttpClient,
    pub network_rx: NetworkReceivers<E>,
}

/// The result of calling `create_api_server`.
///
/// Glue-type between `tests::ApiTester` and `InteractiveTester`.
pub struct ApiServer<T: BeaconChainTypes, SFut: Future<Output = ()>> {
    pub ctx: Arc<Context<T>>,
    pub server: SFut,
    pub listening_socket: SocketAddr,
    pub network_rx: NetworkReceivers<T::EthSpec>,
    pub local_enr: Enr,
    pub external_peer_id: PeerId,
}

type HarnessBuilder<E> = Builder<EphemeralHarnessType<E>>;
type Initializer<E> = Box<dyn FnOnce(HarnessBuilder<E>) -> HarnessBuilder<E>>;
type Mutator<E> = BoxedMutator<E, MemoryStore<E>, MemoryStore<E>>;

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
            ctx,
            server,
            listening_socket,
            network_rx,
            ..
        } = create_api_server(
            harness.chain.clone(),
            &harness.runtime,
            harness.logger().clone(),
        )
        .await;

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
            ctx,
            harness,
            client,
            network_rx,
        }
    }
}

pub async fn create_api_server<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    test_runtime: &TestRuntime,
    log: Logger,
) -> ApiServer<T, impl Future<Output = ()>> {
    // Use port 0 to allocate a new unused port.
    let port = 0;

    let (network_senders, network_receivers) = NetworkSenders::new();

    // Default metadata
    let meta_data = MetaData::V2(MetaDataV2 {
        seq_number: SEQ_NUMBER,
        attnets: EnrAttestationBitfield::<T::EthSpec>::default(),
        syncnets: EnrSyncCommitteeBitfield::<T::EthSpec>::default(),
    });
    let enr_key = CombinedKey::generate_secp256k1();
    let enr = Enr::builder().build(&enr_key).unwrap();
    let network_globals = Arc::new(NetworkGlobals::new(
        enr.clone(),
        meta_data,
        vec![],
        false,
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
    let connection_id = ConnectionId::new_unchecked(1);
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

    let beacon_processor_config = BeaconProcessorConfig {
        // The number of workers must be greater than one. Tests which use the
        // builder workflow sometimes require an internal HTTP request in order
        // to fulfill an already in-flight HTTP request, therefore having only
        // one worker will result in a deadlock.
        max_workers: 2,
        ..BeaconProcessorConfig::default()
    };
    let BeaconProcessorChannels {
        beacon_processor_tx,
        beacon_processor_rx,
        work_reprocessing_tx,
        work_reprocessing_rx,
    } = BeaconProcessorChannels::new(&beacon_processor_config);

    let beacon_processor_send = beacon_processor_tx;
    let reprocess_send = work_reprocessing_tx.clone();
    BeaconProcessor {
        network_globals: network_globals.clone(),
        executor: test_runtime.task_executor.clone(),
        current_workers: 0,
        config: beacon_processor_config,
        log: log.clone(),
    }
    .spawn_manager(
        beacon_processor_rx,
        work_reprocessing_tx,
        work_reprocessing_rx,
        None,
        chain.slot_clock.clone(),
        chain.spec.maximum_gossip_clock_disparity(),
        BeaconProcessorQueueLengths::from_state(
            &chain.canonical_head.cached_head().snapshot.beacon_state,
            &chain.spec,
        )
        .unwrap(),
    )
    .unwrap();

    let ctx = Arc::new(Context {
        config: Config {
            enabled: true,
            listen_port: port,
            data_dir: std::path::PathBuf::from(DEFAULT_ROOT_DIR),
            enable_light_client_server: true,
            ..Config::default()
        },
        chain: Some(chain),
        network_senders: Some(network_senders),
        network_globals: Some(network_globals),
        beacon_processor_send: Some(beacon_processor_send),
        beacon_processor_reprocess_send: Some(reprocess_send),
        eth1_service: Some(eth1_service),
        sse_logging_components: None,
        log,
    });

    let (listening_socket, server) =
        crate::serve(ctx.clone(), test_runtime.task_executor.exit()).unwrap();

    ApiServer {
        ctx,
        server,
        listening_socket,
        network_rx: network_receivers,
        local_enr: enr,
        external_peer_id: peer_id,
    }
}
