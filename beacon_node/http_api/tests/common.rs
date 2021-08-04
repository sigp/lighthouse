use beacon_chain::{
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BeaconChain, BeaconChainTypes,
};
use eth2::{BeaconNodeHttpClient, Timeouts};
use eth2_libp2p::{
    discv5::enr::{CombinedKey, EnrBuilder},
    rpc::methods::{MetaData, MetaDataV2},
    types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield, SyncState},
    Enr, NetworkGlobals, PeerId,
};
use http_api::{Config, Context};
use network::NetworkMessage;
use sensitive_url::SensitiveUrl;
use slog::Logger;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use types::{test_utils::generate_deterministic_keypairs, ChainSpec, EthSpec};

pub const TCP_PORT: u16 = 42;
pub const UDP_PORT: u16 = 42;
pub const SEQ_NUMBER: u64 = 0;
pub const EXTERNAL_ADDR: &str = "/ip4/0.0.0.0/tcp/9000";

/// HTTP API tester that allows interaction with the underlying beacon chain harness.
pub struct InteractiveTester<E: EthSpec> {
    pub harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    pub client: BeaconNodeHttpClient,
    pub network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    _server_shutdown: oneshot::Sender<()>,
}

/// The result of calling `create_api_server`.
///
/// Glue-type between `tests::ApiTester` and `InteractiveTester`.
pub struct ApiServer<E: EthSpec, SFut: Future<Output = ()>> {
    pub server: SFut,
    pub listening_socket: SocketAddr,
    pub shutdown_tx: oneshot::Sender<()>,
    pub network_rx: tokio::sync::mpsc::UnboundedReceiver<NetworkMessage<E>>,
    pub local_enr: Enr,
    pub external_peer_id: PeerId,
}

impl<E: EthSpec> InteractiveTester<E> {
    pub fn new(spec: Option<ChainSpec>, validator_count: usize) -> Self {
        let harness = BeaconChainHarness::new(
            E::default(),
            spec,
            generate_deterministic_keypairs(validator_count),
        );

        let ApiServer {
            server,
            listening_socket,
            shutdown_tx: _server_shutdown,
            network_rx,
            ..
        } = create_api_server(harness.chain.clone(), harness.logger().clone());

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

pub fn create_api_server<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    log: Logger,
) -> ApiServer<T::EthSpec, impl Future<Output = ()>> {
    let (network_tx, network_rx) = mpsc::unbounded_channel();

    // Default metadata
    let meta_data = MetaData::V2(MetaDataV2 {
        seq_number: SEQ_NUMBER,
        attnets: EnrAttestationBitfield::<T::EthSpec>::default(),
        syncnets: EnrSyncCommitteeBitfield::<T::EthSpec>::default(),
    });
    let enr_key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").build(&enr_key).unwrap();
    let network_globals =
        NetworkGlobals::new(enr.clone(), TCP_PORT, UDP_PORT, meta_data, vec![], &log);

    let peer_id = PeerId::random();
    network_globals
        .peers
        .write()
        .connect_ingoing(&peer_id, EXTERNAL_ADDR.parse().unwrap(), None);

    *network_globals.sync_state.write() = SyncState::Synced;

    let eth1_service = eth1::Service::new(eth1::Config::default(), log.clone(), chain.spec.clone());

    let context = Arc::new(Context {
        config: Config {
            enabled: true,
            listen_addr: Ipv4Addr::new(127, 0, 0, 1),
            listen_port: 0,
            allow_origin: None,
            serve_legacy_spec: true,
        },
        chain: Some(chain.clone()),
        network_tx: Some(network_tx),
        network_globals: Some(Arc::new(network_globals)),
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
        network_rx,
        local_enr: enr,
        external_peer_id: peer_id,
    }
}
