use crate::{Config, Context};
use beacon_chain::{
    BeaconChain, BeaconChainTypes,
    custody_context::NodeCustodyType,
    test_utils::{BeaconChainHarness, BoxedMutator, Builder, EphemeralHarnessType},
};
use beacon_processor::{
    BeaconProcessor, BeaconProcessorChannels, BeaconProcessorConfig, BeaconProcessorQueueLengths,
};
use directory::DEFAULT_ROOT_DIR;
use eth2::{BeaconNodeHttpClient, Timeouts};
use lighthouse_network::rpc::methods::MetaDataV3;
use lighthouse_network::{
    ConnectedPoint, Enr, NetworkConfig, NetworkGlobals, PeerId, PeerManager,
    discv5::enr::CombinedKey,
    libp2p::swarm::{
        ConnectionId, NetworkBehaviour,
        behaviour::{ConnectionEstablished, FromSwarm},
    },
    rpc::methods::{MetaData, MetaDataV2},
    types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield, SyncState},
};
use network::{NetworkReceivers, NetworkSenders};
use sensitive_url::SensitiveUrl;
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
        Self::new_with_initializer_and_mutator(
            spec,
            validator_count,
            None,
            None,
            Config::default(),
            true,
            NodeCustodyType::Fullnode,
        )
        .await
    }

    pub async fn new_supernode(spec: Option<ChainSpec>, validator_count: usize) -> Self {
        Self::new_with_initializer_and_mutator(
            spec,
            validator_count,
            None,
            None,
            Config::default(),
            true,
            NodeCustodyType::Supernode,
        )
        .await
    }

    pub async fn new_with_initializer_and_mutator(
        spec: Option<ChainSpec>,
        validator_count: usize,
        initializer: Option<Initializer<E>>,
        mutator: Option<Mutator<E>>,
        config: Config,
        use_mock_builder: bool,
        node_custody_type: NodeCustodyType,
    ) -> Self {
        let mut harness_builder = BeaconChainHarness::builder(E::default())
            .spec_or_default(spec.map(Arc::new))
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

        harness_builder = harness_builder.node_custody_type(node_custody_type);

        // Add a mutator for the beacon chain builder which will be called in
        // `HarnessBuilder::build`.
        if let Some(mutator) = mutator {
            harness_builder = harness_builder.initial_mutator(mutator);
        }

        let mut harness = harness_builder.build();

        let ApiServer {
            ctx,
            server,
            listening_socket,
            network_rx,
            ..
        } = create_api_server_with_config(harness.chain.clone(), config, &harness.runtime).await;

        tokio::spawn(server);

        // Late-initalize the mock builder now that the mock execution node and beacon API ports
        // have been allocated.
        let beacon_api_ip = listening_socket.ip();
        let beacon_api_port = listening_socket.port();
        let beacon_url =
            SensitiveUrl::parse(format!("http://{beacon_api_ip}:{beacon_api_port}").as_str())
                .unwrap();

        // We disable apply_operations because it breaks the mock builder's ability to return
        // payloads.
        let apply_operations = false;

        // We disable strict registration checks too, because it makes HTTP tests less fiddly to
        // write.
        let strict_registrations = false;

        // Broadcast to the BN only if Fulu is scheduled. In the broadcast validation tests we want
        // to infer things from the builder return code, and pre-Fulu it's simpler to let the BN
        // handle broadcast and return detailed codes. Post-Fulu the builder doesn't return the
        // block at all, so we *need* the builder to do the broadcast and return a 400 if the block
        // is invalid.
        let broadcast_to_bn = ctx.chain.as_ref().unwrap().spec.is_fulu_scheduled();

        if use_mock_builder {
            let mock_builder_server = harness.set_mock_builder(
                beacon_url.clone(),
                strict_registrations,
                apply_operations,
                broadcast_to_bn,
            );

            tokio::spawn(mock_builder_server);
        }

        // Use 5s timeouts on CI, as there are several sources of artifical slowness, including
        // mock-builder.
        let timeouts = Timeouts {
            default: Duration::from_secs(5),
            ..Timeouts::set_all(Duration::from_secs(5))
        };
        let client = BeaconNodeHttpClient::new(beacon_url.clone(), timeouts);

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
) -> ApiServer<T, impl Future<Output = ()> + use<T>> {
    create_api_server_with_config(chain, Config::default(), test_runtime).await
}

pub async fn create_api_server_with_config<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    http_config: Config,
    test_runtime: &TestRuntime,
) -> ApiServer<T, impl Future<Output = ()> + use<T>> {
    // Use port 0 to allocate a new unused port.
    let port = 0;

    let (network_senders, network_receivers) = NetworkSenders::new();

    // Default metadata
    let meta_data = if chain.spec.is_peer_das_scheduled() {
        MetaData::V3(MetaDataV3 {
            seq_number: SEQ_NUMBER,
            attnets: EnrAttestationBitfield::<T::EthSpec>::default(),
            syncnets: EnrSyncCommitteeBitfield::<T::EthSpec>::default(),
            custody_group_count: chain.spec.custody_requirement,
        })
    } else {
        MetaData::V2(MetaDataV2 {
            seq_number: SEQ_NUMBER,
            attnets: EnrAttestationBitfield::<T::EthSpec>::default(),
            syncnets: EnrSyncCommitteeBitfield::<T::EthSpec>::default(),
        })
    };

    let enr_key = CombinedKey::generate_secp256k1();
    let enr = Enr::builder().build(&enr_key).unwrap();
    let network_config = Arc::new(NetworkConfig::default());
    let network_globals = Arc::new(NetworkGlobals::new(
        enr.clone(),
        meta_data,
        vec![],
        false,
        network_config,
        chain.spec.clone(),
    ));

    // Only a peer manager can add peers, so we create a dummy manager.
    let config = lighthouse_network::peer_manager::config::Config::default();
    let mut pm = PeerManager::new(config, network_globals.clone()).unwrap();

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
    } = BeaconProcessorChannels::new(&beacon_processor_config);

    let beacon_processor_send = beacon_processor_tx;
    BeaconProcessor {
        network_globals: network_globals.clone(),
        executor: test_runtime.task_executor.clone(),
        current_workers: 0,
        config: beacon_processor_config,
    }
    .spawn_manager(
        beacon_processor_rx,
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
        // Override several config fields with defaults. If these need to be tweaked in future
        // we could remove these overrides.
        config: Config {
            enabled: true,
            listen_port: port,
            data_dir: std::path::PathBuf::from(DEFAULT_ROOT_DIR),
            ..http_config
        },
        chain: Some(chain),
        network_senders: Some(network_senders),
        network_globals: Some(network_globals),
        beacon_processor_send: Some(beacon_processor_send),
        sse_logging_components: None,
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
