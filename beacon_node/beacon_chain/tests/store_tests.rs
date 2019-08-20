#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy};
use lmd_ghost::ThreadSafeReducedTree;
use parking_lot::RwLock;
use rand::Rng;
use std::sync::Arc;
use store::{HotColdDB, Store};
use tempfile::{tempdir, TempDir};
use tree_hash::TreeHash;
use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use types::*;

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

type TestForkChoice = ThreadSafeReducedTree<HotColdDB, MinimalEthSpec>;
type E = MinimalEthSpec;

fn get_store(db_path: &TempDir) -> Arc<RwLock<HotColdDB>> {
    let spec = Arc::new(MinimalEthSpec::default_spec());
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    Arc::new(RwLock::new(
        HotColdDB::open(&hot_path, &cold_path, spec).unwrap(),
    ))
}

fn get_harness(
    store: Arc<RwLock<HotColdDB>>,
    validator_count: usize,
) -> BeaconChainHarness<TestForkChoice, MinimalEthSpec, HotColdDB> {
    let harness = BeaconChainHarness::from_keypairs(KEYPAIRS[0..validator_count].to_vec(), store);

    harness.advance_slot();

    harness
}

#[test]
fn full_participation_no_skips() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let state = &harness.chain.head().beacon_state;

    assert_eq!(
        state.slot, num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint.epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint.epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );

    let finalized_epoch = state.current_epoch() - 2;

    assert_eq!(
        dbg!(store.read().get_split_slot()),
        finalized_epoch.start_slot(E::slots_per_epoch())
    );

    // Chain dump should contain all the blocks, and the stored states should match their
    // state roots.
    let chain_dump = harness.chain.chain_dump().unwrap();

    assert_eq!(chain_dump.len(), num_blocks_produced as usize + 1);

    for checkpoint in chain_dump {
        assert_eq!(
            checkpoint.beacon_state_root,
            Hash256::from_slice(&checkpoint.beacon_state.tree_hash_root()),
            "tree hash of stored state is incorrect"
        );
    }
}
