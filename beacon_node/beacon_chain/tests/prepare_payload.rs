#![cfg(not(debug_assertions))]
#![allow(clippy::result_large_err)]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType, test_spec,
};
use beacon_chain::{ChainConfig, custody_context::NodeCustodyType};
use bls::Keypair;
use logging::create_test_tracing_subscriber;
use slot_clock::SlotClock;
use std::sync::{Arc, LazyLock};
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tempfile::{TempDir, tempdir};
use types::*;

// Should ideally be divisible by 3.
pub const LOW_VALIDATOR_COUNT: usize = 32;
pub const HIGH_VALIDATOR_COUNT: usize = 64;

// When set to true, cache any states fetched from the db.
pub const CACHE_STATE_IN_TESTS: bool = true;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(HIGH_VALIDATOR_COUNT));

type E = MinimalEthSpec;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;

fn get_store(db_path: &TempDir) -> Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>> {
    let store_config = StoreConfig {
        prune_payloads: false,
        ..StoreConfig::default()
    };
    get_store_generic(db_path, store_config, test_spec::<E>())
}

fn get_store_generic(
    db_path: &TempDir,
    config: StoreConfig,
    spec: ChainSpec,
) -> Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>> {
    create_test_tracing_subscriber();
    let hot_path = db_path.path().join("chain_db");
    let cold_path = db_path.path().join("freezer_db");
    let blobs_path = db_path.path().join("blobs_db");

    HotColdDB::open(
        &hot_path,
        &cold_path,
        &blobs_path,
        |_, _, _| Ok(()),
        config,
        spec.into(),
    )
    .expect("disk store should initialize")
}

fn get_harness(
    store: Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>>,
    validator_count: usize,
) -> TestHarness {
    // Most tests expect to retain historic states, so we use this as the default.
    let chain_config = ChainConfig {
        archive: true,
        ..ChainConfig::default()
    };
    get_harness_generic(
        store,
        validator_count,
        chain_config,
        NodeCustodyType::Fullnode,
    )
}

fn get_harness_generic(
    store: Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>>,
    validator_count: usize,
    chain_config: ChainConfig,
    node_custody_type: NodeCustodyType,
) -> TestHarness {
    let harness = TestHarness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store)
        .mock_execution_layer()
        .chain_config(chain_config)
        .node_custody_type(node_custody_type)
        .build();
    harness.advance_slot();
    harness
}

#[tokio::test]
async fn prepare_payload_on_full_parent() {
    // Post-Gloas test.
    if !test_spec::<E>()
        .fork_name_at_slot::<E>(Slot::new(0))
        .gloas_enabled()
    {
        return;
    }

    let num_blocks_produced = E::slots_per_epoch();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Produce a block with a payload that affects withdrawals for the next slot.
    // This requires injecting at least one valid and actionable withdrawal into the execution
    // requests. The mock builder needs updating to support this.
    // TODO(claude): fill this in

    // Verify that the withdrawals computed from the block's state differ from the withdrawal's
    // computed from the block's state with its payload applied by
    // `apply_parent_execution_payload`.
    // TODO(claude): fill this in

    // Call `prepare_beacon_proposer` for the next slot and ensure that it primes the execution
    // layer payload attributes cache with the correct withdrawals (the ones taking into account
    // the applied execution_requests).
    // TODO(claude): fill this in
}
