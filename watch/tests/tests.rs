#![recursion_limit = "256"]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use eth2::types::BlockId;
use http_api::test_utils::{create_api_server, ApiServer};
use network::NetworkMessage;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use types::{Hash256, MainnetEthSpec, Slot};
use url::Url;
use watch::{
    client::WatchHttpClient,
    database::Config,
    server::{start_server, Context},
    update_service::{self, BACKFILL_SLOT_COUNT},
};

type E = MainnetEthSpec;

const VALIDATOR_COUNT: usize = 32;

struct Tester {
    pub harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    pub client: WatchHttpClient,
    pub config: Config,
    _bn_network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    _bn_api_shutdown_tx: oneshot::Sender<()>,
    _watch_shutdown_tx: oneshot::Sender<()>,
}

impl Tester {
    pub async fn new() -> Self {
        let harness = BeaconChainHarness::builder(E::default())
            .default_spec()
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .build();
        harness.advance_slot();

        /*
         * Spawn a Beacon Node HTTP API.
         */

        let ApiServer {
            server,
            listening_socket: bn_api_listening_socket,
            shutdown_tx: _bn_api_shutdown_tx,
            network_rx: _bn_network_rx,
            ..
        } = create_api_server(harness.chain.clone(), harness.logger().clone()).await;
        tokio::spawn(server);

        /*
         * Spawn a Watch HTTP API.
         */
        let mut config = Config::default();
        config.server_listen_port = 0;
        config.beacon_node_url = format!(
            "http://{}:{}",
            bn_api_listening_socket.ip(),
            bn_api_listening_socket.port()
        );

        let (_watch_shutdown_tx, watch_shutdown_rx) = oneshot::channel();
        let ctx: Context<E> = Context {
            config: config.clone(),
            _phantom: <_>::default(),
        };
        let (watch_listening_socket, watch_server) = start_server(Arc::new(ctx), async {
            let _ = watch_shutdown_rx.await;
        })
        .unwrap();
        tokio::spawn(watch_server);

        /*
         * Create a HTTP client to talk to the watch HTTP API.
         */

        let client = WatchHttpClient {
            client: reqwest::Client::new(),
            server: Url::parse(&format!(
                "http://{}:{}",
                watch_listening_socket.ip(),
                watch_listening_socket.port()
            ))
            .unwrap(),
        };

        Self {
            harness,
            client,
            config,
            _bn_network_rx,
            _bn_api_shutdown_tx,
            _watch_shutdown_tx,
        }
    }

    /// Extend the chain on the beacon chain harness. Do not update watch.
    pub fn extend_chain(self, num_blocks: usize) -> Self {
        self.harness.extend_chain(
            num_blocks,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        );
        self
    }

    /// Run the watch updater service.
    pub async fn run_update_service(self, num_runs: usize) -> Self {
        for _ in 0..num_runs {
            update_service::run_once::<E>(&self.config).await.unwrap();
        }
        self
    }

    pub async fn assert_no_canonical_chain(self) -> Self {
        let lowest_slot = self.client.get_lowest_canonical_slot().await.unwrap();

        assert_eq!(lowest_slot, None);

        self
    }

    /// Check that the canonical chain in watch matches that of the harness. Also check that all
    /// canonical blocks can be retrieved.
    pub async fn assert_canonical_chain_consistent(self) -> Self {
        let head_root = self.harness.chain.head_info().unwrap().block_root;
        let chain: Vec<(Hash256, Slot)> = self
            .harness
            .chain
            .rev_iter_block_roots_from(head_root)
            .unwrap()
            .map(Result::unwrap)
            .collect();

        for (root, slot) in &chain {
            let block = self
                .client
                .get_beacon_blocks(BlockId::Root(*root))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(block.slot, *slot);
        }

        self
    }
}

#[tokio::test]
async fn short_chain() {
    Tester::new()
        .await
        .extend_chain(BACKFILL_SLOT_COUNT / 2)
        .assert_no_canonical_chain()
        .await
        .run_update_service(1)
        .await
        .assert_canonical_chain_consistent()
        .await;
}

#[tokio::test]
async fn long_chain() {
    Tester::new()
        .await
        .extend_chain(BACKFILL_SLOT_COUNT * 3)
        .assert_no_canonical_chain()
        .await
        .run_update_service(3)
        .await
        .assert_canonical_chain_consistent()
        .await;
}
