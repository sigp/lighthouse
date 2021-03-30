#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy},
    BeaconChain, BeaconChainTypes,
};
use sloggers::{null::NullLoggerBuilder, Build};
use std::sync::Arc;
use store::{HotColdDB, LevelDB, StoreConfig};
use tempfile::{tempdir, TempDir};
use types::{EthSpec, Keypair, MinimalEthSpec};

type E = MinimalEthSpec;

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_store(db_path: &TempDir) -> Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>> {
    let spec = E::default_spec();
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    let config = StoreConfig::default();
    let log = NullLoggerBuilder.build().expect("logger should build");
    HotColdDB::open(&hot_path, &cold_path, |_, _, _| Ok(()), config, spec, log)
        .expect("disk store should initialize")
}

#[test]
fn finalizes_after_resuming_from_db() {
    let validator_count = 16;
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 8;
    let first_half = num_blocks_produced / 2;

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    let harness = BeaconChainHarness::new_with_disk_store(
        MinimalEthSpec,
        store.clone(),
        KEYPAIRS[0..validator_count].to_vec(),
    );

    harness.advance_slot();

    harness.extend_chain(
        first_half as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    assert!(
        harness
            .chain
            .head()
            .expect("should read head")
            .beacon_state
            .finalized_checkpoint
            .epoch
            > 0,
        "the chain should have already finalized"
    );

    let latest_slot = harness.chain.slot().expect("should have a slot");

    harness
        .chain
        .persist_head_and_fork_choice()
        .expect("should persist the head and fork choice");
    harness
        .chain
        .persist_op_pool()
        .expect("should persist the op pool");
    harness
        .chain
        .persist_eth1_cache()
        .expect("should persist the eth1 cache");

    let data_dir = harness.data_dir;
    let original_chain = harness.chain;

    let resumed_harness = BeaconChainHarness::resume_from_disk_store(
        MinimalEthSpec,
        store,
        KEYPAIRS[0..validator_count].to_vec(),
        data_dir,
    );

    assert_chains_pretty_much_the_same(&original_chain, &resumed_harness.chain);

    // Set the slot clock of the resumed harness to be in the slot following the previous harness.
    //
    // This allows us to produce the block at the next slot.
    resumed_harness
        .chain
        .slot_clock
        .set_slot(latest_slot.as_u64() + 1);

    resumed_harness.extend_chain(
        (num_blocks_produced - first_half) as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let state = &resumed_harness
        .chain
        .head()
        .expect("should read head")
        .beacon_state;
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
}

/// Checks that two chains are the same, for the purpose of this tests.
///
/// Several fields that are hard/impossible to check are ignored (e.g., the store).
fn assert_chains_pretty_much_the_same<T: BeaconChainTypes>(a: &BeaconChain<T>, b: &BeaconChain<T>) {
    assert_eq!(a.spec, b.spec, "spec should be equal");
    assert_eq!(a.op_pool, b.op_pool, "op_pool should be equal");
    assert_eq!(
        a.head().unwrap(),
        b.head().unwrap(),
        "head() should be equal"
    );
    assert_eq!(a.heads(), b.heads(), "heads() should be equal");
    assert_eq!(
        a.genesis_block_root, b.genesis_block_root,
        "genesis_block_root should be equal"
    );

    let slot = a.slot().unwrap();
    assert!(
        a.fork_choice.write().get_head(slot).unwrap()
            == b.fork_choice.write().get_head(slot).unwrap(),
        "fork_choice heads should be equal"
    );
}
