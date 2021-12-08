#![recursion_limit = "256"]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use eth2::{types::BlockId, BeaconNodeHttpClient};
use http_api::test_utils::{create_api_server, ApiServer};
use network::NetworkMessage;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use types::{Hash256, MainnetEthSpec, Slot};
use url::Url;
use watch::{
    client::WatchHttpClient,
    database::{Config, Database},
    server::{start_server, Context},
    update_service::{self, *},
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
         * Create a watch configuration
         */

        let mut config = Config::default();
        config.server_listen_port = 0;
        // Use a random string for a database name. It's not ideal to introduce entropy into tests,
        // but I think this should be fine since it shouldn't impact functionality.
        config.dbname = random_dbname();
        // Drop the database if it exists, to ensure a clean slate.
        config.drop_dbname = true;
        config.beacon_node_url = format!(
            "http://{}:{}",
            bn_api_listening_socket.ip(),
            bn_api_listening_socket.port()
        );

        /*
         * Create a temporary postgres db
         */

        Database::create(&config).await.unwrap();

        /*
         * Spawn a Watch HTTP API.
         */

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

    async fn get_db_and_bn(&self) -> (Database, BeaconNodeHttpClient) {
        let db = get_db_connection(&self.config).await.unwrap();
        let bn = get_beacon_client(&self.config).unwrap();
        (db, bn)
    }

    pub async fn perform_head_update(self) -> Self {
        let (mut db, bn) = self.get_db_and_bn().await;
        perform_head_update::<E>(&mut db, &bn).await.unwrap();
        self
    }

    pub async fn perform_backfill(self, max_slots: usize) -> Self {
        let (mut db, bn) = self.get_db_and_bn().await;
        perform_backfill::<E>(&mut db, &bn, max_slots)
            .await
            .unwrap();
        self
    }

    pub async fn update_unknown_blocks(self, max_blocks: i64) -> Self {
        let (mut db, bn) = self.get_db_and_bn().await;
        update_unknown_blocks(&mut db, &bn, max_blocks)
            .await
            .unwrap();
        self
    }

    pub async fn assert_canonical_slots_empty(self) -> Self {
        let lowest_slot = self.client.get_lowest_canonical_slot().await.unwrap();

        assert_eq!(lowest_slot, None);

        self
    }

    pub async fn assert_canonical_slots_not_empty(self) -> Self {
        self.client
            .get_lowest_canonical_slot()
            .await
            .unwrap()
            .unwrap();

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

impl Drop for Tester {
    fn drop(&mut self) {
        let config = self.config.clone();
        tokio::spawn(async move { Database::drop_database(&config).await });
    }
}

pub fn random_dbname() -> String {
    let mut s: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    // Postgres gets weird about capitals in database names.
    s.make_ascii_lowercase();
    s
}

#[tokio::test]
async fn short_chain() {
    Tester::new()
        .await
        .extend_chain(BACKFILL_SLOT_COUNT / 2)
        .assert_canonical_slots_empty()
        .await
        .run_update_service(1)
        .await
        .assert_canonical_slots_not_empty()
        .await
        .assert_canonical_chain_consistent()
        .await;
}

#[tokio::test]
async fn long_chain() {
    Tester::new()
        .await
        .extend_chain(BACKFILL_SLOT_COUNT * 3)
        .assert_canonical_slots_empty()
        .await
        .perform_head_update()
        .await
        /*
         * Perform three separate backfills.
         */
        .perform_backfill(BACKFILL_SLOT_COUNT)
        .await
        .perform_backfill(BACKFILL_SLOT_COUNT)
        .await
        .perform_backfill(BACKFILL_SLOT_COUNT)
        .await
        /*
         * Insert blocks in three separate routines.
         */
        .update_unknown_blocks(BACKFILL_SLOT_COUNT as i64)
        .await
        .update_unknown_blocks(BACKFILL_SLOT_COUNT as i64)
        .await
        .update_unknown_blocks(BACKFILL_SLOT_COUNT as i64)
        .await
        // Capture genesis block
        .update_unknown_blocks(1)
        .await
        .assert_canonical_slots_not_empty()
        .await
        .assert_canonical_chain_consistent()
        .await;
}
