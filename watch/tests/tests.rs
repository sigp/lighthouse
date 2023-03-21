#![recursion_limit = "256"]
#![cfg(unix)]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use eth2::{types::BlockId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use http_api::test_utils::{create_api_server, ApiServer};
use network::NetworkReceivers;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use tokio::sync::oneshot;
use types::{Hash256, MainnetEthSpec, Slot};
use url::Url;
use watch::{
    client::WatchHttpClient,
    config::Config,
    database::{self, Config as DatabaseConfig, PgPool, WatchSlot},
    server::{start_server, Config as ServerConfig},
    updater::{handler::*, run_updater, Config as UpdaterConfig, WatchSpec},
};

use log::error;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{runtime, task::JoinHandle};
use tokio_postgres::{config::Config as PostgresConfig, Client, NoTls};
use unused_port::unused_tcp4_port;

use testcontainers::{clients::Cli, images::postgres::Postgres, RunnableImage};

type E = MainnetEthSpec;

const VALIDATOR_COUNT: usize = 32;
const SLOTS_PER_EPOCH: u64 = 32;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

fn build_test_config(config: &DatabaseConfig) -> PostgresConfig {
    let mut postgres_config = PostgresConfig::new();
    postgres_config
        .user(&config.user)
        .password(&config.password)
        .dbname(&config.default_dbname)
        .host(&config.host)
        .port(config.port)
        .connect_timeout(Duration::from_millis(config.connect_timeout_millis));
    postgres_config
}

async fn connect(config: &DatabaseConfig) -> (Client, JoinHandle<()>) {
    let db_config = build_test_config(config);
    let (client, conn) = db_config
        .connect(NoTls)
        .await
        .expect("Could not connect to db");
    let connection = runtime::Handle::current().spawn(async move {
        if let Err(e) = conn.await {
            error!("Connection error {:?}", e);
        }
    });

    (client, connection)
}

pub async fn create_test_database(config: &DatabaseConfig) {
    let (db, _) = connect(config).await;

    db.execute(&format!("CREATE DATABASE {};", config.dbname), &[])
        .await
        .expect("Database creation failed");
}

struct TesterBuilder {
    pub harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    pub config: Config,
    _bn_network_rx: NetworkReceivers<E>,
    _bn_api_shutdown_tx: oneshot::Sender<()>,
}

impl TesterBuilder {
    pub async fn new() -> TesterBuilder {
        let harness = BeaconChainHarness::builder(E::default())
            .default_spec()
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .build();

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
        let database_port = unused_tcp4_port().expect("Unable to find unused port.");
        let server_port = unused_tcp4_port().expect("Unable to find unused port.");
        let config = Config {
            database: DatabaseConfig {
                dbname: random_dbname(),
                port: database_port,
                ..Default::default()
            },
            server: ServerConfig {
                listen_port: server_port,
                ..Default::default()
            },
            updater: UpdaterConfig {
                beacon_node_url: format!(
                    "http://{}:{}",
                    bn_api_listening_socket.ip(),
                    bn_api_listening_socket.port()
                ),
                ..Default::default()
            },
            ..Default::default()
        };

        Self {
            harness,
            config,
            _bn_network_rx,
            _bn_api_shutdown_tx,
        }
    }
    pub async fn build(self, pool: PgPool) -> Tester {
        /*
         * Spawn a Watch HTTP API.
         */
        let (_watch_shutdown_tx, watch_shutdown_rx) = oneshot::channel();
        let watch_server = start_server(&self.config, SLOTS_PER_EPOCH, pool, async {
            let _ = watch_shutdown_rx.await;
        })
        .unwrap();
        tokio::spawn(watch_server);

        let addr = SocketAddr::new(
            self.config.server.listen_addr,
            self.config.server.listen_port,
        );

        /*
         * Create a HTTP client to talk to the watch HTTP API.
         */
        let client = WatchHttpClient {
            client: reqwest::Client::new(),
            server: Url::parse(&format!("http://{}:{}", addr.ip(), addr.port())).unwrap(),
        };

        /*
         * Create a HTTP client to talk to the Beacon Node API.
         */
        let beacon_node_url = SensitiveUrl::parse(&self.config.updater.beacon_node_url).unwrap();
        let bn = BeaconNodeHttpClient::new(beacon_node_url, Timeouts::set_all(DEFAULT_TIMEOUT));
        let spec = WatchSpec::mainnet("mainnet".to_string());

        /*
         * Build update service
         */
        let updater = UpdateHandler::new(bn, spec, self.config.clone())
            .await
            .unwrap();

        Tester {
            harness: self.harness,
            client,
            config: self.config,
            updater,
            _bn_network_rx: self._bn_network_rx,
            _bn_api_shutdown_tx: self._bn_api_shutdown_tx,
            _watch_shutdown_tx,
        }
    }
    async fn initialize_database(&self) -> PgPool {
        create_test_database(&self.config.database).await;
        database::utils::run_migrations(&self.config.database);
        database::build_connection_pool(&self.config.database)
            .expect("Could not build connection pool")
    }
}

struct Tester {
    pub harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    pub client: WatchHttpClient,
    pub config: Config,
    pub updater: UpdateHandler<E>,
    _bn_network_rx: NetworkReceivers<E>,
    _bn_api_shutdown_tx: oneshot::Sender<()>,
    _watch_shutdown_tx: oneshot::Sender<()>,
}

impl Tester {
    /// Extend the chain on the beacon chain harness. Do not update the beacon watch database.
    pub async fn extend_chain(&mut self, num_blocks: u64) -> &mut Self {
        self.harness.advance_slot();
        self.harness
            .extend_chain(
                num_blocks as usize,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
        self
    }

    // Advance the slot clock without a block. This results in a skipped slot.
    pub fn skip_slot(&mut self) -> &mut Self {
        self.harness.advance_slot();
        self
    }

    // Perform a single slot re-org.
    pub async fn reorg_chain(&mut self) -> &mut Self {
        let previous_slot = self.harness.get_current_slot();
        self.harness.advance_slot();
        let first_slot = self.harness.get_current_slot();
        self.harness
            .extend_chain(
                1,
                BlockStrategy::ForkCanonicalChainAt {
                    previous_slot,
                    first_slot,
                },
                AttestationStrategy::AllValidators,
            )
            .await;
        self
    }

    /// Run the watch updater service.
    pub async fn run_update_service(&mut self, num_runs: usize) -> &mut Self {
        for _ in 0..num_runs {
            run_updater(self.config.clone()).await.unwrap();
        }
        self
    }

    pub async fn perform_head_update(&mut self) -> &mut Self {
        self.updater.perform_head_update().await.unwrap();
        self
    }

    pub async fn perform_backfill(&mut self) -> &mut Self {
        self.updater.backfill_canonical_slots().await.unwrap();
        self
    }

    pub async fn update_unknown_blocks(&mut self) -> &mut Self {
        self.updater.update_unknown_blocks().await.unwrap();
        self
    }

    pub async fn update_validator_set(&mut self) -> &mut Self {
        self.updater.update_validator_set().await.unwrap();
        self
    }

    pub async fn fill_suboptimal_attestations(&mut self) -> &mut Self {
        self.updater.fill_suboptimal_attestations().await.unwrap();

        self
    }

    pub async fn backfill_suboptimal_attestations(&mut self) -> &mut Self {
        self.updater
            .backfill_suboptimal_attestations()
            .await
            .unwrap();

        self
    }

    pub async fn fill_block_rewards(&mut self) -> &mut Self {
        self.updater.fill_block_rewards().await.unwrap();

        self
    }

    pub async fn backfill_block_rewards(&mut self) -> &mut Self {
        self.updater.backfill_block_rewards().await.unwrap();

        self
    }

    pub async fn fill_block_packing(&mut self) -> &mut Self {
        self.updater.fill_block_packing().await.unwrap();

        self
    }

    pub async fn backfill_block_packing(&mut self) -> &mut Self {
        self.updater.backfill_block_packing().await.unwrap();

        self
    }

    pub async fn assert_canonical_slots_empty(&mut self) -> &mut Self {
        let lowest_slot = self
            .client
            .get_lowest_canonical_slot()
            .await
            .unwrap()
            .map(|slot| slot.slot.as_slot());

        assert_eq!(lowest_slot, None);

        self
    }

    pub async fn assert_lowest_canonical_slot(&mut self, expected: u64) -> &mut Self {
        let slot = self
            .client
            .get_lowest_canonical_slot()
            .await
            .unwrap()
            .unwrap()
            .slot
            .as_slot();

        assert_eq!(slot, Slot::new(expected));

        self
    }

    pub async fn assert_highest_canonical_slot(&mut self, expected: u64) -> &mut Self {
        let slot = self
            .client
            .get_highest_canonical_slot()
            .await
            .unwrap()
            .unwrap()
            .slot
            .as_slot();

        assert_eq!(slot, Slot::new(expected));

        self
    }

    pub async fn assert_canonical_slots_not_empty(&mut self) -> &mut Self {
        self.client
            .get_lowest_canonical_slot()
            .await
            .unwrap()
            .unwrap();

        self
    }

    pub async fn assert_slot_is_skipped(&mut self, slot: u64) -> &mut Self {
        assert!(self
            .client
            .get_beacon_blocks(BlockId::Slot(Slot::new(slot)))
            .await
            .unwrap()
            .is_none());
        self
    }

    pub async fn assert_all_validators_exist(&mut self) -> &mut Self {
        assert_eq!(
            self.client
                .get_all_validators()
                .await
                .unwrap()
                .unwrap()
                .len(),
            VALIDATOR_COUNT
        );
        self
    }

    pub async fn assert_lowest_block_has_proposer_info(&mut self) -> &mut Self {
        let mut block = self
            .client
            .get_lowest_beacon_block()
            .await
            .unwrap()
            .unwrap();

        if block.slot.as_slot() == 0 {
            block = self
                .client
                .get_next_beacon_block(block.root.as_hash())
                .await
                .unwrap()
                .unwrap()
        }

        self.client
            .get_proposer_info(BlockId::Root(block.root.as_hash()))
            .await
            .unwrap()
            .unwrap();

        self
    }

    pub async fn assert_highest_block_has_proposer_info(&mut self) -> &mut Self {
        let block = self
            .client
            .get_highest_beacon_block()
            .await
            .unwrap()
            .unwrap();

        self.client
            .get_proposer_info(BlockId::Root(block.root.as_hash()))
            .await
            .unwrap()
            .unwrap();

        self
    }

    pub async fn assert_lowest_block_has_block_rewards(&mut self) -> &mut Self {
        let mut block = self
            .client
            .get_lowest_beacon_block()
            .await
            .unwrap()
            .unwrap();

        if block.slot.as_slot() == 0 {
            block = self
                .client
                .get_next_beacon_block(block.root.as_hash())
                .await
                .unwrap()
                .unwrap()
        }

        self.client
            .get_block_reward(BlockId::Root(block.root.as_hash()))
            .await
            .unwrap()
            .unwrap();

        self
    }

    pub async fn assert_highest_block_has_block_rewards(&mut self) -> &mut Self {
        let block = self
            .client
            .get_highest_beacon_block()
            .await
            .unwrap()
            .unwrap();

        self.client
            .get_block_reward(BlockId::Root(block.root.as_hash()))
            .await
            .unwrap()
            .unwrap();

        self
    }

    pub async fn assert_lowest_block_has_block_packing(&mut self) -> &mut Self {
        let mut block = self
            .client
            .get_lowest_beacon_block()
            .await
            .unwrap()
            .unwrap();

        while block.slot.as_slot() <= SLOTS_PER_EPOCH {
            block = self
                .client
                .get_next_beacon_block(block.root.as_hash())
                .await
                .unwrap()
                .unwrap()
        }

        self.client
            .get_block_packing(BlockId::Root(block.root.as_hash()))
            .await
            .unwrap()
            .unwrap();

        self
    }

    pub async fn assert_highest_block_has_block_packing(&mut self) -> &mut Self {
        let block = self
            .client
            .get_highest_beacon_block()
            .await
            .unwrap()
            .unwrap();

        self.client
            .get_block_packing(BlockId::Root(block.root.as_hash()))
            .await
            .unwrap()
            .unwrap();

        self
    }

    /// Check that the canonical chain in watch matches that of the harness. Also check that all
    /// canonical blocks can be retrieved.
    pub async fn assert_canonical_chain_consistent(&mut self, last_slot: u64) -> &mut Self {
        let head_root = self.harness.chain.head_beacon_block_root();
        let mut chain: Vec<(Hash256, Slot)> = self
            .harness
            .chain
            .rev_iter_block_roots_from(head_root)
            .unwrap()
            .map(Result::unwrap)
            .collect();

        // `chain` contains skip slots, but the `watch` API will not return blocks that do not
        // exist.
        // We need to filter them out.
        chain.reverse();
        chain.dedup_by(|(hash1, _), (hash2, _)| hash1 == hash2);

        // Remove any slots below `last_slot` since it is known that the database has not
        // backfilled past it.
        chain.retain(|(_, slot)| slot.as_u64() >= last_slot);

        for (root, slot) in &chain {
            let block = self
                .client
                .get_beacon_blocks(BlockId::Root(*root))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(block.slot.as_slot(), *slot);
        }

        self
    }

    /// Check that every block in the `beacon_blocks` table has corresponding entries in the
    /// `proposer_info`, `block_rewards` and `block_packing` tables.
    pub async fn assert_all_blocks_have_metadata(&mut self) -> &mut Self {
        let pool = database::build_connection_pool(&self.config.database).unwrap();

        let mut conn = database::get_connection(&pool).unwrap();
        let highest_block_slot = database::get_highest_beacon_block(&mut conn)
            .unwrap()
            .unwrap()
            .slot
            .as_slot();
        let lowest_block_slot = database::get_lowest_beacon_block(&mut conn)
            .unwrap()
            .unwrap()
            .slot
            .as_slot();
        for slot in lowest_block_slot.as_u64()..=highest_block_slot.as_u64() {
            let canonical_slot = database::get_canonical_slot(&mut conn, WatchSlot::new(slot))
                .unwrap()
                .unwrap();
            if !canonical_slot.skipped {
                database::get_block_rewards_by_slot(&mut conn, WatchSlot::new(slot))
                    .unwrap()
                    .unwrap();
                database::get_proposer_info_by_slot(&mut conn, WatchSlot::new(slot))
                    .unwrap()
                    .unwrap();
                database::get_block_packing_by_slot(&mut conn, WatchSlot::new(slot))
                    .unwrap()
                    .unwrap();
            }
        }

        self
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
    format!("test_{}", s)
}

#[cfg(unix)]
#[tokio::test]
async fn short_chain() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;

    tester
        .extend_chain(16)
        .await
        .assert_canonical_slots_empty()
        .await
        .run_update_service(1)
        .await
        .assert_all_validators_exist()
        .await
        .assert_canonical_slots_not_empty()
        .await
        .assert_canonical_chain_consistent(0)
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn short_chain_sync_starts_on_skip_slot() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;

    tester
        .skip_slot()
        .skip_slot()
        .extend_chain(6)
        .await
        .skip_slot()
        .extend_chain(6)
        .await
        .skip_slot()
        .assert_canonical_slots_empty()
        .await
        .run_update_service(1)
        .await
        .assert_all_validators_exist()
        .await
        .assert_canonical_slots_not_empty()
        .await
        .assert_canonical_chain_consistent(0)
        .await
        .assert_lowest_block_has_block_rewards()
        .await
        .assert_highest_block_has_block_rewards()
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn short_chain_with_skip_slot() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;

    tester
        .extend_chain(5)
        .await
        .assert_canonical_slots_empty()
        .await
        .run_update_service(1)
        .await
        .assert_all_validators_exist()
        .await
        .assert_canonical_slots_not_empty()
        .await
        .assert_highest_canonical_slot(5)
        .await
        .assert_lowest_canonical_slot(0)
        .await
        .assert_canonical_chain_consistent(0)
        .await
        .skip_slot()
        .extend_chain(1)
        .await
        .run_update_service(1)
        .await
        .assert_all_validators_exist()
        .await
        .assert_highest_canonical_slot(7)
        .await
        .assert_slot_is_skipped(6)
        .await
        .assert_canonical_chain_consistent(0)
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn short_chain_with_reorg() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;

    tester
        .extend_chain(5)
        .await
        .assert_canonical_slots_empty()
        .await
        .run_update_service(1)
        .await
        .assert_all_validators_exist()
        .await
        .assert_canonical_slots_not_empty()
        .await
        .assert_highest_canonical_slot(5)
        .await
        .assert_lowest_canonical_slot(0)
        .await
        .assert_canonical_chain_consistent(0)
        .await
        .skip_slot()
        .reorg_chain()
        .await
        .extend_chain(1)
        .await
        .run_update_service(1)
        .await
        .assert_all_validators_exist()
        .await
        .assert_highest_canonical_slot(8)
        .await
        .assert_slot_is_skipped(6)
        .await
        .assert_canonical_chain_consistent(0)
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn chain_grows() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;

    // Apply four blocks to the chain.
    tester
        .extend_chain(4)
        .await
        .perform_head_update()
        .await
        // Head update should insert the head block.
        .assert_highest_canonical_slot(4)
        .await
        // And also backfill to the epoch boundary.
        .assert_lowest_canonical_slot(0)
        .await
        // Fill back to genesis.
        .perform_backfill()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(4)
        .await
        // Apply one block to the chain.
        .extend_chain(1)
        .await
        .perform_head_update()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(5)
        .await
        // Apply two blocks to the chain.
        .extend_chain(2)
        .await
        // Update the head.
        .perform_head_update()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(7)
        .await
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // Check the chain is consistent
        .assert_canonical_chain_consistent(0)
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn chain_grows_with_metadata() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;

    tester
        // Apply four blocks to the chain.
        .extend_chain(4)
        .await
        .perform_head_update()
        .await
        // Head update should insert the head block.
        .assert_highest_canonical_slot(4)
        .await
        // And also backfill to the epoch boundary.
        .assert_lowest_canonical_slot(0)
        .await
        // Fill back to genesis.
        .perform_backfill()
        .await
        // Insert all validators
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // All validators should be present.
        .assert_all_validators_exist()
        .await
        // Check the chain is consistent
        .assert_canonical_chain_consistent(0)
        .await
        // Get other chain data.
        // Backfill before forward fill to ensure order is arbitrary.
        .backfill_block_rewards()
        .await
        .fill_block_rewards()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(4)
        .await
        // All rewards should be present.
        .assert_lowest_block_has_block_rewards()
        .await
        .assert_highest_block_has_block_rewards()
        .await
        // All proposers should be present.
        .assert_lowest_block_has_proposer_info()
        .await
        .assert_highest_block_has_proposer_info()
        .await
        // Apply one block to the chain.
        .extend_chain(1)
        .await
        .perform_head_update()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(5)
        .await
        // Apply two blocks to the chain.
        .extend_chain(2)
        .await
        // Update the head.
        .perform_head_update()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(7)
        .await
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // Check the chain is consistent
        .assert_canonical_chain_consistent(0)
        .await
        // Get other chain data.
        .fill_block_rewards()
        .await
        .backfill_block_rewards()
        .await
        // All rewards should be present.
        .assert_lowest_block_has_block_rewards()
        .await
        .assert_highest_block_has_block_rewards()
        .await
        // All proposers should be present.
        .assert_lowest_block_has_proposer_info()
        .await
        .assert_highest_block_has_proposer_info()
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn chain_grows_with_metadata_and_multiple_skip_slots() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;

    // Apply four blocks to the chain.
    tester
        .extend_chain(4)
        .await
        .perform_head_update()
        .await
        // Head update should insert the head block.
        .assert_highest_canonical_slot(4)
        // And also backfill to the epoch boundary.
        .await
        .assert_lowest_canonical_slot(0)
        .await
        // Fill back to genesis.
        .perform_backfill()
        .await
        // Insert all validators
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // All validators should be present.
        .assert_all_validators_exist()
        .await
        // Check the chain is consistent.
        .assert_canonical_chain_consistent(0)
        .await
        // Get other chain data.
        .fill_block_rewards()
        .await
        .backfill_block_rewards()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(4)
        .await
        // All rewards should be present.
        .assert_lowest_block_has_block_rewards()
        .await
        .assert_highest_block_has_block_rewards()
        .await
        // All proposers should be present.
        .assert_lowest_block_has_proposer_info()
        .await
        .assert_highest_block_has_proposer_info()
        .await
        // Add multiple skip slots.
        .skip_slot()
        .skip_slot()
        .skip_slot()
        // Apply one block to the chain.
        .extend_chain(1)
        .await
        .perform_head_update()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(8)
        .await
        // Apply two blocks to the chain.
        .extend_chain(2)
        .await
        // Update the head.
        .perform_head_update()
        .await
        // All validators should be present.
        .assert_all_validators_exist()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(10)
        .await
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // Check the chain is consistent
        .assert_canonical_chain_consistent(0)
        .await
        // Get other chain data.
        // Backfill before forward fill to ensure order is arbitrary.
        .backfill_block_rewards()
        .await
        .fill_block_rewards()
        .await
        // All rewards should be present.
        .assert_lowest_block_has_block_rewards()
        .await
        .assert_highest_block_has_block_rewards()
        .await
        // All proposers should be present.
        .assert_lowest_block_has_proposer_info()
        .await
        .assert_highest_block_has_proposer_info()
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn chain_grows_to_second_epoch() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;
    // Apply 40 blocks to the chain.
    tester
        .extend_chain(40)
        .await
        .perform_head_update()
        .await
        // Head update should insert the head block.
        .assert_highest_canonical_slot(40)
        .await
        // And also backfill to the epoch boundary.
        .assert_lowest_canonical_slot(32)
        .await
        // Fill back to genesis.
        .perform_backfill()
        .await
        // Insert all validators
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // All validators should be present.
        .assert_all_validators_exist()
        .await
        // Check the chain is consistent.
        .assert_canonical_chain_consistent(0)
        .await
        // Get block packings.
        .fill_block_packing()
        .await
        .backfill_block_packing()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(40)
        .await
        // All packings should be present.
        .assert_lowest_block_has_block_packing()
        .await
        .assert_highest_block_has_block_packing()
        .await
        // Skip a slot
        .skip_slot()
        // Apply two blocks to the chain.
        .extend_chain(2)
        .await
        // Update the head.
        .perform_head_update()
        .await
        // All blocks should be present.
        .assert_lowest_canonical_slot(0)
        .await
        .assert_highest_canonical_slot(43)
        .await
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // Update new block_packing
        // Backfill before forward fill to ensure order is arbitrary
        .backfill_block_packing()
        .await
        .fill_block_packing()
        .await
        // All packings should be present.
        .assert_lowest_block_has_block_packing()
        .await
        .assert_highest_block_has_block_packing()
        .await
        // Check the chain is consistent
        .assert_canonical_chain_consistent(0)
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn large_chain() {
    let builder = TesterBuilder::new().await;

    let docker = Cli::default();
    let image = RunnableImage::from(Postgres::default())
        .with_mapped_port((builder.config.database.port, 5432));
    let _node = docker.run(image);

    let pool = builder.initialize_database().await;
    let mut tester = builder.build(pool).await;
    // Apply 40 blocks to the chain.
    tester
        .extend_chain(400)
        .await
        .perform_head_update()
        .await
        // Head update should insert the head block.
        .assert_highest_canonical_slot(400)
        .await
        // And also backfill to the epoch boundary.
        .assert_lowest_canonical_slot(384)
        .await
        // Backfill 2 epochs as per default config.
        .perform_backfill()
        .await
        // Insert all validators
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // All validators should be present.
        .assert_all_validators_exist()
        .await
        // Check the chain is consistent.
        .assert_canonical_chain_consistent(384)
        .await
        // Get block rewards and proposer info.
        .fill_block_rewards()
        .await
        .backfill_block_rewards()
        .await
        // Get block packings.
        .fill_block_packing()
        .await
        .backfill_block_packing()
        .await
        // Should have backfilled 2 more epochs.
        .assert_lowest_canonical_slot(320)
        .await
        .assert_highest_canonical_slot(400)
        .await
        // All rewards should be present.
        .assert_lowest_block_has_block_rewards()
        .await
        .assert_highest_block_has_block_rewards()
        .await
        // All proposers should be present.
        .assert_lowest_block_has_proposer_info()
        .await
        .assert_highest_block_has_proposer_info()
        .await
        // All packings should be present.
        .assert_lowest_block_has_block_packing()
        .await
        .assert_highest_block_has_block_packing()
        .await
        // Skip a slot
        .skip_slot()
        // Apply two blocks to the chain.
        .extend_chain(2)
        .await
        // Update the head.
        .perform_head_update()
        .await
        .perform_backfill()
        .await
        // Should have backfilled 2 more epochs
        .assert_lowest_canonical_slot(256)
        .await
        .assert_highest_canonical_slot(403)
        .await
        // Update validators
        .update_validator_set()
        .await
        // Insert all blocks.
        .update_unknown_blocks()
        .await
        // All validators should be present.
        .assert_all_validators_exist()
        .await
        // Get suboptimal attestations.
        .fill_suboptimal_attestations()
        .await
        .backfill_suboptimal_attestations()
        .await
        // Get block rewards and proposer info.
        .fill_block_rewards()
        .await
        .backfill_block_rewards()
        .await
        // Get block packing.
        // Backfill before forward fill to ensure order is arbitrary.
        .backfill_block_packing()
        .await
        .fill_block_packing()
        .await
        // All rewards should be present.
        .assert_lowest_block_has_block_rewards()
        .await
        .assert_highest_block_has_block_rewards()
        .await
        // All proposers should be present.
        .assert_lowest_block_has_proposer_info()
        .await
        .assert_highest_block_has_proposer_info()
        .await
        // All packings should be present.
        .assert_lowest_block_has_block_packing()
        .await
        .assert_highest_block_has_block_packing()
        .await
        // Check the chain is consistent.
        .assert_canonical_chain_consistent(256)
        .await
        // Check every block has rewards, proposer info and packing statistics.
        .assert_all_blocks_have_metadata()
        .await;
}
