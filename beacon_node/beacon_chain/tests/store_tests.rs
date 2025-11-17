#![cfg(not(debug_assertions))]

use beacon_chain::attestation_verification::Error as AttnError;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::builder::BeaconChainBuilder;
use beacon_chain::custody_context::CUSTODY_CHANGE_DA_EFFECTIVE_DELAY_SECONDS;
use beacon_chain::data_availability_checker::AvailableBlock;
use beacon_chain::historical_data_columns::HistoricalDataColumnError;
use beacon_chain::schema_change::migrate_schema;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType, get_kzg,
    mock_execution_layer_from_parts, test_spec,
};
use beacon_chain::test_utils::{SyncCommitteeStrategy, generate_data_column_indices_rand_order};
use beacon_chain::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BeaconSnapshot, BlockError, ChainConfig,
    NotifyExecutionLayer, ServerSentEventHandler, WhenSlotSkipped,
    beacon_proposer_cache::{
        compute_proposer_duties_from_head, ensure_state_can_determine_proposers_for_epoch,
    },
    custody_context::NodeCustodyType,
    data_availability_checker::MaybeAvailableBlock,
    historical_blocks::HistoricalBlockError,
    migrate::MigratorConfig,
};
use logging::create_test_tracing_subscriber;
use maplit::hashset;
use rand::Rng;
use rand::rngs::StdRng;
use slot_clock::{SlotClock, TestingSlotClock};
use state_processing::{BlockReplayer, state_advance::complete_state_advance};
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use store::database::interface::BeaconNodeBackend;
use store::metadata::{CURRENT_SCHEMA_VERSION, STATE_UPPER_LIMIT_NO_RETAIN, SchemaVersion};
use store::{
    BlobInfo, DBColumn, HotColdDB, StoreConfig,
    hdiff::HierarchyConfig,
    iter::{BlockRootsIterator, StateRootsIterator},
};
use tempfile::{TempDir, tempdir};
use tracing::info;
use types::test_utils::{SeedableRng, XorShiftRng};
use types::*;

// Should ideally be divisible by 3.
pub const LOW_VALIDATOR_COUNT: usize = 24;
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
        reconstruct_historic_states: true,
        ..ChainConfig::default()
    };
    get_harness_generic(
        store,
        validator_count,
        chain_config,
        NodeCustodyType::Fullnode,
    )
}

fn get_harness_import_all_data_columns(
    store: Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>>,
    validator_count: usize,
) -> TestHarness {
    // Most tests expect to retain historic states, so we use this as the default.
    let chain_config = ChainConfig {
        reconstruct_historic_states: true,
        ..ChainConfig::default()
    };
    get_harness_generic(
        store,
        validator_count,
        chain_config,
        NodeCustodyType::Supernode,
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

fn get_states_descendant_of_block(
    store: &HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>,
    block_root: Hash256,
) -> Vec<(Hash256, Slot)> {
    let summaries = store.load_hot_state_summaries().unwrap();
    summaries
        .iter()
        .filter(|(_, s)| s.latest_block_root == block_root)
        .map(|(state_root, summary)| (*state_root, summary.slot))
        .collect()
}

#[tokio::test]
async fn light_client_bootstrap_test() {
    let spec = test_spec::<E>();
    let Some(_) = spec.altair_fork_epoch else {
        // No-op prior to Altair.
        return;
    };

    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), spec.clone());
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let all_validators = (0..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();
    let num_initial_slots = E::slots_per_epoch() * 7;
    let slots: Vec<Slot> = (1..num_initial_slots).map(Slot::new).collect();

    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    harness
        .add_attested_blocks_at_slots_with_lc_data(
            genesis_state.clone(),
            genesis_state_root,
            &slots,
            &all_validators,
            None,
            SyncCommitteeStrategy::NoValidators,
        )
        .await;

    let finalized_checkpoint = harness
        .chain
        .canonical_head
        .cached_head()
        .finalized_checkpoint();

    let block_root = finalized_checkpoint.root;

    let (lc_bootstrap, _) = harness
        .chain
        .get_light_client_bootstrap(&block_root)
        .unwrap()
        .unwrap();

    let bootstrap_slot = match lc_bootstrap {
        LightClientBootstrap::Altair(lc_bootstrap) => lc_bootstrap.header.beacon.slot,
        LightClientBootstrap::Capella(lc_bootstrap) => lc_bootstrap.header.beacon.slot,
        LightClientBootstrap::Deneb(lc_bootstrap) => lc_bootstrap.header.beacon.slot,
        LightClientBootstrap::Electra(lc_bootstrap) => lc_bootstrap.header.beacon.slot,
        LightClientBootstrap::Fulu(lc_bootstrap) => lc_bootstrap.header.beacon.slot,
        LightClientBootstrap::Gloas(lc_bootstrap) => lc_bootstrap.header.beacon.slot,
    };

    assert_eq!(
        bootstrap_slot.epoch(E::slots_per_epoch()),
        finalized_checkpoint.epoch
    );
}

#[tokio::test]
async fn light_client_updates_test() {
    let spec = test_spec::<E>();
    let Some(_) = spec.altair_fork_epoch else {
        // No-op prior to Altair.
        return;
    };

    let num_final_blocks = E::slots_per_epoch() * 2;
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), test_spec::<E>());
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let all_validators = (0..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();
    let num_initial_slots = E::slots_per_epoch() * 10;
    let slots: Vec<Slot> = (1..num_initial_slots).map(Slot::new).collect();

    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    harness
        .add_attested_blocks_at_slots(
            genesis_state.clone(),
            genesis_state_root,
            &slots,
            &all_validators,
        )
        .await;

    harness.advance_slot();
    harness
        .extend_chain_with_light_client_data(
            num_final_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let current_state = harness.get_current_state();

    // calculate the sync period from the previous slot
    let sync_period = (current_state.slot() - Slot::new(1))
        .epoch(E::slots_per_epoch())
        .sync_committee_period(&spec)
        .unwrap();

    // fetch a range of light client updates. right now there should only be one light client update
    // in the db.
    let lc_updates = harness
        .chain
        .get_light_client_updates(sync_period, 100)
        .unwrap();

    assert_eq!(lc_updates.len(), 1);

    // Advance to the next sync committee period
    for _i in 0..(E::slots_per_epoch() * u64::from(spec.epochs_per_sync_committee_period)) {
        harness.advance_slot();
    }

    harness
        .extend_chain_with_light_client_data(
            num_final_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // we should now have two light client updates in the db
    let lc_updates = harness
        .chain
        .get_light_client_updates(sync_period, 100)
        .unwrap();

    assert_eq!(lc_updates.len(), 2);
}

#[tokio::test]
async fn full_participation_no_skips() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
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
    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);
}

#[tokio::test]
async fn randomised_skips() {
    let num_slots = E::slots_per_epoch() * 5;
    let mut num_blocks_produced = 0;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let rng = &mut XorShiftRng::from_seed([42; 16]);

    let mut head_slot = 0;

    for slot in 1..=num_slots {
        if rng.random_bool(0.8) {
            harness
                .extend_chain(
                    1,
                    BlockStrategy::ForkCanonicalChainAt {
                        previous_slot: Slot::new(head_slot),
                        first_slot: Slot::new(slot),
                    },
                    AttestationStrategy::AllValidators,
                )
                .await;
            harness.advance_slot();
            num_blocks_produced += 1;
            head_slot = slot;
        } else {
            harness.advance_slot();
        }
    }

    let state = &harness.chain.head_snapshot().beacon_state;

    assert_eq!(
        state.slot(),
        num_slots,
        "head should be at the current slot"
    );

    check_split_slot(&harness, store.clone());
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);
}

#[tokio::test]
async fn long_skip() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Number of blocks to create in the first run, intentionally not falling on an epoch
    // boundary in order to check that the DB hot -> cold migration is capable of reaching
    // back across the skip distance, and correctly migrating those extra non-finalized states.
    let initial_blocks = E::slots_per_epoch() * 5 + E::slots_per_epoch() / 2;
    let skip_slots = E::slots_per_historical_root() as u64 * 8;
    // Create the minimum ~2.5 epochs of extra blocks required to re-finalize the chain.
    // Having this set lower ensures that we start justifying and finalizing quickly after a skip.
    let final_blocks = 2 * E::slots_per_epoch() + E::slots_per_epoch() / 2;

    harness
        .extend_chain(
            initial_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    check_finalization(&harness, initial_blocks);

    // 2. Skip slots
    for _ in 0..skip_slots {
        harness.advance_slot();
    }

    // 3. Produce more blocks, establish a new finalized epoch
    harness
        .extend_chain(
            final_blocks as usize,
            BlockStrategy::ForkCanonicalChainAt {
                previous_slot: Slot::new(initial_blocks),
                first_slot: Slot::new(initial_blocks + skip_slots + 1),
            },
            AttestationStrategy::AllValidators,
        )
        .await;

    check_finalization(&harness, initial_blocks + skip_slots + final_blocks);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, initial_blocks + final_blocks + 1);
    check_iterators(&harness);
}

/// Go forward to the point where the genesis randao value is no longer part of the vector.
///
/// This implicitly checks that:
/// 1. The chunked vector scheme doesn't attempt to store an incorrect genesis value
/// 2. We correctly load the genesis value for all required slots
/// NOTE: this test takes about a minute to run
#[tokio::test]
async fn randao_genesis_storage() {
    let validator_count = 8;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), validator_count);

    let num_slots = E::slots_per_epoch() * (E::epochs_per_historical_vector() - 1) as u64;

    // Check we have a non-trivial genesis value
    let genesis_value = *harness
        .chain
        .head_snapshot()
        .beacon_state
        .get_randao_mix(Epoch::new(0))
        .expect("randao mix ok");
    assert!(!genesis_value.is_zero());

    harness
        .extend_chain(
            num_slots as usize - 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Check that genesis value is still present
    assert!(
        harness
            .chain
            .head_snapshot()
            .beacon_state
            .randao_mixes()
            .iter()
            .any(|x| *x == genesis_value)
    );

    // Then upon adding one more block, it isn't
    harness.advance_slot();
    harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    assert!(
        !harness
            .chain
            .head_snapshot()
            .beacon_state
            .randao_mixes()
            .iter()
            .any(|x| *x == genesis_value)
    );

    check_finalization(&harness, num_slots);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_slots + 1);
    check_iterators(&harness);
}

// Check that closing and reopening a freezer DB restores the split slot to its correct value.
#[tokio::test]
async fn split_slot_restore() {
    let db_path = tempdir().unwrap();

    let split_slot = {
        let store = get_store(&db_path);
        let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

        let num_blocks = 4 * E::slots_per_epoch();

        harness
            .extend_chain(
                num_blocks as usize,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        store.get_split_slot()
    };
    assert_ne!(split_slot, Slot::new(0));

    // Re-open the store
    let store = get_store(&db_path);

    assert_eq!(store.get_split_slot(), split_slot);
}

// Check attestation processing and `load_epoch_boundary_state` in the presence of a split DB.
// This is a bit of a monster test in that it tests lots of different things, but until they're
// tested elsewhere, this is as good a place as any.
#[tokio::test]
async fn epoch_boundary_state_attestation_processing() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let late_validators = vec![0, 1];
    let timely_validators = (2..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();

    let mut late_attestations = vec![];

    for _ in 0..num_blocks_produced {
        harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::SomeValidators(timely_validators.clone()),
            )
            .await;

        let head = harness.chain.head_snapshot();
        late_attestations.extend(harness.get_single_attestations(
            &AttestationStrategy::SomeValidators(late_validators.clone()),
            &head.beacon_state,
            head.beacon_state_root(),
            head.beacon_block_root,
            head.beacon_block.slot(),
        ));

        harness.advance_slot();
    }

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store.clone());
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);

    let mut checked_pre_fin = false;

    for (attestation, subnet_id) in late_attestations.into_iter().flatten() {
        // load_epoch_boundary_state is idempotent!
        let block_root = attestation.data.beacon_block_root;
        let block = store
            .get_blinded_block(&block_root)
            .unwrap()
            .expect("block exists");
        // Use get_state as the state may be finalized by this point
        let mut epoch_boundary_state = store
            .get_state(&block.state_root(), None, CACHE_STATE_IN_TESTS)
            .expect("no error")
            .unwrap_or_else(|| {
                panic!("epoch boundary state should exist {:?}", block.state_root())
            });
        let ebs_state_root = epoch_boundary_state.update_tree_hash_cache().unwrap();
        let mut ebs_of_ebs = store
            .get_state(&ebs_state_root, None, CACHE_STATE_IN_TESTS)
            .expect("no error")
            .unwrap_or_else(|| panic!("ebs of ebs should exist {ebs_state_root:?}"));
        ebs_of_ebs.apply_pending_mutations().unwrap();
        assert_eq!(epoch_boundary_state, ebs_of_ebs);

        // If the attestation is pre-finalization it should be rejected.
        let finalized_epoch = harness.finalized_checkpoint().epoch;

        let res = harness
            .chain
            .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id));

        let current_slot = harness.chain.slot().expect("should get slot");
        let expected_attestation_slot = attestation.data.slot;
        // Extra -1 to handle gossip clock disparity.
        let expected_earliest_permissible_slot = current_slot - E::slots_per_epoch() - 1;

        if expected_attestation_slot <= finalized_epoch.start_slot(E::slots_per_epoch())
            || expected_attestation_slot < expected_earliest_permissible_slot
        {
            checked_pre_fin = true;
            assert!(matches!(
                res.err().unwrap(),
                AttnError::PastSlot {
                    attestation_slot,
                    earliest_permissible_slot,
                }
                if attestation_slot == expected_attestation_slot && earliest_permissible_slot == expected_earliest_permissible_slot
            ));
        } else {
            res.expect("should have verified attetation");
        }
    }
    assert!(checked_pre_fin);
}

// Test that the `end_slot` for forwards block and state root iterators works correctly.
#[tokio::test]
async fn forwards_iter_block_and_state_roots_until() {
    let num_blocks_produced = E::slots_per_epoch() * 17;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let all_validators = &harness.get_all_validators();
    let (mut head_state, mut head_state_root) = harness.get_current_state_and_root();
    let head_block_root = harness.head_block_root();
    let mut block_roots = vec![head_block_root];
    let mut state_roots = vec![head_state_root];

    for slot in (1..=num_blocks_produced).map(Slot::from) {
        let (block_root, mut state) = harness
            .add_attested_block_at_slot(slot, head_state, head_state_root, all_validators)
            .await
            .unwrap();
        head_state_root = state.update_tree_hash_cache().unwrap();
        head_state = state;
        block_roots.push(block_root.into());
        state_roots.push(head_state_root);
    }

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store.clone());

    // The freezer upper bound slot is the point at which the hybrid forwards iterator behaviour
    // changes.
    let block_upper_bound = store
        .freezer_upper_bound_for_column(DBColumn::BeaconBlockRoots, Slot::new(0))
        .unwrap()
        .unwrap();
    assert!(block_upper_bound > 0);
    let state_upper_bound = store
        .freezer_upper_bound_for_column(DBColumn::BeaconStateRoots, Slot::new(0))
        .unwrap()
        .unwrap();
    assert!(state_upper_bound > 0);
    assert_eq!(state_upper_bound, block_upper_bound);

    let chain = &harness.chain;
    let head_state = harness.get_current_state();
    let head_slot = head_state.slot();
    assert_eq!(head_slot, num_blocks_produced);

    let test_range = |start_slot: Slot, end_slot: Slot| {
        let mut block_root_iter = chain
            .forwards_iter_block_roots_until(start_slot, end_slot)
            .unwrap();
        let mut state_root_iter = chain
            .forwards_iter_state_roots_until(start_slot, end_slot)
            .unwrap();

        for slot in (start_slot.as_u64()..=end_slot.as_u64()).map(Slot::new) {
            let block_root = block_roots[slot.as_usize()];
            assert_eq!(block_root_iter.next().unwrap().unwrap(), (block_root, slot));

            let state_root = state_roots[slot.as_usize()];
            assert_eq!(state_root_iter.next().unwrap().unwrap(), (state_root, slot));
        }
    };

    let split_slot = store.get_split_slot();
    assert_eq!(split_slot, block_upper_bound);

    test_range(Slot::new(0), split_slot);
    test_range(split_slot, split_slot);
    test_range(split_slot - 1, split_slot);
    test_range(Slot::new(0), split_slot - 1);
    test_range(Slot::new(0), head_state.slot());
}

#[tokio::test]
async fn block_replayer_hooks() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let chain = &harness.chain;

    let block_slots = vec![1, 3, 5, 10, 11, 12, 13, 14, 31, 32, 33]
        .into_iter()
        .map(Slot::new)
        .collect::<Vec<_>>();
    let max_slot = *block_slots.last().unwrap();
    let all_slots = (0..=max_slot.as_u64()).map(Slot::new).collect::<Vec<_>>();

    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    let (_, _, end_block_root, mut end_state) = harness
        .add_attested_blocks_at_slots(state.clone(), state_root, &block_slots, &all_validators)
        .await;

    let blocks = store
        .load_blocks_to_replay(Slot::new(0), max_slot, end_block_root.into())
        .unwrap();

    let mut pre_slots = vec![];
    let mut post_slots = vec![];
    let mut pre_block_slots = vec![];
    let mut post_block_slots = vec![];

    let mut replay_state = BlockReplayer::<MinimalEthSpec>::new(state, &chain.spec)
        .pre_slot_hook(Box::new(|_, state| {
            pre_slots.push(state.slot());
            Ok(())
        }))
        .post_slot_hook(Box::new(|state, epoch_summary, is_skip_slot| {
            if is_skip_slot {
                assert!(!block_slots.contains(&state.slot()));
            } else {
                assert!(block_slots.contains(&state.slot()));
            }
            if state.slot() % E::slots_per_epoch() == 0 {
                assert!(epoch_summary.is_some());
            }
            post_slots.push(state.slot());
            Ok(())
        }))
        .pre_block_hook(Box::new(|state, block| {
            assert_eq!(state.slot(), block.slot());
            pre_block_slots.push(block.slot());
            Ok(())
        }))
        .post_block_hook(Box::new(|state, block| {
            assert_eq!(state.slot(), block.slot());
            post_block_slots.push(block.slot());
            Ok(())
        }))
        .apply_blocks(blocks, None)
        .unwrap()
        .into_state();

    // All but last slot seen by pre-slot hook
    assert_eq!(&pre_slots, all_slots.split_last().unwrap().1);
    // All but 0th slot seen by post-slot hook
    assert_eq!(&post_slots, all_slots.split_first().unwrap().1);
    // All blocks seen by both hooks
    assert_eq!(pre_block_slots, block_slots);
    assert_eq!(post_block_slots, block_slots);

    // States match.
    end_state.apply_pending_mutations().unwrap();
    replay_state.apply_pending_mutations().unwrap();
    end_state.drop_all_caches().unwrap();
    replay_state.drop_all_caches().unwrap();
    assert_eq!(end_state, replay_state);
}

#[tokio::test]
async fn delete_blocks_and_states() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let unforked_blocks: u64 = 4 * E::slots_per_epoch();

    // Finalize an initial portion of the chain.
    let initial_slots: Vec<Slot> = (1..=unforked_blocks).map(Into::into).collect();
    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    harness
        .add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators)
        .await;

    // Create a fork post-finalization.
    let two_thirds = (LOW_VALIDATOR_COUNT / 3) * 2;
    let honest_validators: Vec<usize> = (0..two_thirds).collect();
    let faulty_validators: Vec<usize> = (two_thirds..LOW_VALIDATOR_COUNT).collect();

    let fork_blocks = 2 * E::slots_per_epoch();

    let slot_u64: u64 = harness.get_current_slot().as_u64() + 1;

    let fork1_slots: Vec<Slot> = (slot_u64..(slot_u64 + fork_blocks))
        .map(Into::into)
        .collect();
    let fork2_slots: Vec<Slot> = (slot_u64 + 1..(slot_u64 + 1 + fork_blocks))
        .map(Into::into)
        .collect();

    let fork1_state = harness.get_current_state();
    let fork2_state = fork1_state.clone();
    let results = harness
        .add_blocks_on_multiple_chains(vec![
            (fork1_state, fork1_slots, honest_validators),
            (fork2_state, fork2_slots, faulty_validators),
        ])
        .await;

    let honest_head = results[0].2;
    let faulty_head = results[1].2;

    assert_ne!(honest_head, faulty_head, "forks should be distinct");
    assert_eq!(harness.head_slot(), unforked_blocks + fork_blocks);

    assert_eq!(
        harness.head_block_root(),
        Hash256::from(honest_head),
        "the honest chain should be the canonical chain",
    );

    let faulty_head_block = store
        .get_blinded_block(&faulty_head.into())
        .expect("no errors")
        .expect("faulty head block exists");

    let faulty_head_state = store
        .get_state(
            &faulty_head_block.state_root(),
            Some(faulty_head_block.slot()),
            CACHE_STATE_IN_TESTS,
        )
        .expect("no db error")
        .expect("faulty head state exists");

    // Delete faulty fork
    // Attempting to load those states should find them unavailable
    for (state_root, slot) in
        StateRootsIterator::new(&store, &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks {
            break;
        }
        store.delete_state(&state_root, slot).unwrap();
        assert_eq!(
            store
                .get_state(&state_root, Some(slot), CACHE_STATE_IN_TESTS)
                .unwrap(),
            None
        );
    }

    // Double-deleting should also be OK (deleting non-existent things is fine)
    for (state_root, slot) in
        StateRootsIterator::new(&store, &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks {
            break;
        }
        store.delete_state(&state_root, slot).unwrap();
    }

    // Deleting the blocks from the fork should remove them completely
    for (block_root, slot) in
        BlockRootsIterator::new(&store, &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks + 1 {
            break;
        }
        store.delete_block(&block_root).unwrap();
        assert_eq!(store.get_blinded_block(&block_root).unwrap(), None);
    }

    // Deleting frozen states should do nothing
    let split_slot = store.get_split_slot();
    let finalized_states = harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap);

    for (state_root, slot) in finalized_states {
        if slot < split_slot {
            store.delete_state(&state_root, slot).unwrap();
        }
    }

    // After all that, the chain dump should still be OK
    check_chain_dump(&harness, unforked_blocks + fork_blocks + 1);
}

// Check that we never produce invalid blocks when there is deep forking that changes the shuffling.
// See https://github.com/sigp/lighthouse/issues/845
async fn multi_epoch_fork_valid_blocks_test(
    initial_blocks: usize,
    num_fork1_blocks_: usize,
    num_fork2_blocks_: usize,
    num_fork1_validators: usize,
) -> (TempDir, TestHarness, Hash256, Hash256) {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let validators_keypairs =
        types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
    let harness = TestHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();

    let num_fork1_blocks: u64 = num_fork1_blocks_.try_into().unwrap();
    let num_fork2_blocks: u64 = num_fork2_blocks_.try_into().unwrap();

    // Create the initial portion of the chain
    if initial_blocks > 0 {
        let initial_slots: Vec<Slot> = (1..=initial_blocks).map(Into::into).collect();
        let (state, state_root) = harness.get_current_state_and_root();
        let all_validators = harness.get_all_validators();
        harness
            .add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators)
            .await;
    }

    assert!(num_fork1_validators <= LOW_VALIDATOR_COUNT);
    let fork1_validators: Vec<usize> = (0..num_fork1_validators).collect();
    let fork2_validators: Vec<usize> = (num_fork1_validators..LOW_VALIDATOR_COUNT).collect();

    let fork1_state = harness.get_current_state();
    let fork2_state = fork1_state.clone();

    let slot_u64: u64 = harness.get_current_slot().as_u64() + 1;
    let fork1_slots: Vec<Slot> = (slot_u64..(slot_u64 + num_fork1_blocks))
        .map(Into::into)
        .collect();
    let fork2_slots: Vec<Slot> = (slot_u64 + 1..(slot_u64 + 1 + num_fork2_blocks))
        .map(Into::into)
        .collect();

    let results = harness
        .add_blocks_on_multiple_chains(vec![
            (fork1_state, fork1_slots, fork1_validators),
            (fork2_state, fork2_slots, fork2_validators),
        ])
        .await;

    let head1 = results[0].2;
    let head2 = results[1].2;

    (db_path, harness, head1.into(), head2.into())
}

// This is the minimal test of block production with different shufflings.
#[tokio::test]
async fn block_production_different_shuffling_early() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    multi_epoch_fork_valid_blocks_test(
        slots_per_epoch - 2,
        slots_per_epoch + 3,
        slots_per_epoch + 3,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;
}

#[tokio::test]
async fn block_production_different_shuffling_long() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch - 2,
        3 * slots_per_epoch,
        3 * slots_per_epoch,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;
}

// Check that the op pool safely includes multiple attestations per block when necessary.
// This checks the correctness of the shuffling compatibility memoization.
#[tokio::test]
async fn multiple_attestations_per_block() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store, HIGH_VALIDATOR_COUNT);

    harness
        .extend_chain(
            E::slots_per_epoch() as usize * 3,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();

    let committees_per_slot = head
        .beacon_state
        .get_committee_count_at_slot(head.beacon_state.slot())
        .unwrap();
    assert!(committees_per_slot > 1);

    for snapshot in harness.chain.chain_dump().unwrap() {
        let slot = snapshot.beacon_block.slot();
        let fork_name = harness.chain.spec.fork_name_at_slot::<E>(slot);

        if fork_name.electra_enabled() {
            assert_eq!(
                snapshot
                    .beacon_block
                    .as_ref()
                    .message()
                    .body()
                    .attestations_len() as u64,
                if slot <= 1 { 0 } else { 1 }
            );
        } else {
            assert_eq!(
                snapshot
                    .beacon_block
                    .as_ref()
                    .message()
                    .body()
                    .attestations_len() as u64,
                if slot <= 1 { 0 } else { committees_per_slot }
            );
        }
    }
}

#[tokio::test]
async fn shuffling_compatible_linear_chain() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let head_block_root = harness
        .extend_chain(
            4 * E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    check_shuffling_compatible(
        &harness,
        &get_state_for_block(&harness, head_block_root),
        head_block_root,
    );
}

#[tokio::test]
async fn shuffling_compatible_missing_pivot_block() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Skip the block at the end of the first epoch.
    harness
        .extend_chain(
            E::slots_per_epoch() as usize - 2,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    harness.advance_slot();
    harness.advance_slot();
    let head_block_root = harness
        .extend_chain(
            2 * E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    check_shuffling_compatible(
        &harness,
        &get_state_for_block(&harness, head_block_root),
        head_block_root,
    );
}

#[tokio::test]
async fn shuffling_compatible_simple_fork() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let (db_path, harness, head1, head2) = multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch,
        3 * slots_per_epoch,
        3 * slots_per_epoch,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;

    let head1_state = get_state_for_block(&harness, head1);
    let head2_state = get_state_for_block(&harness, head2);

    check_shuffling_compatible(&harness, &head1_state, head1);
    check_shuffling_compatible(&harness, &head1_state, head2);
    check_shuffling_compatible(&harness, &head2_state, head1);
    check_shuffling_compatible(&harness, &head2_state, head2);

    drop(db_path);
}

#[tokio::test]
async fn shuffling_compatible_short_fork() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let (db_path, harness, head1, head2) = multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch - 2,
        slots_per_epoch + 2,
        slots_per_epoch + 2,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;

    let head1_state = get_state_for_block(&harness, head1);
    let head2_state = get_state_for_block(&harness, head2);

    check_shuffling_compatible(&harness, &head1_state, head1);
    check_shuffling_compatible(&harness, &head1_state, head2);
    check_shuffling_compatible(&harness, &head2_state, head1);
    check_shuffling_compatible(&harness, &head2_state, head2);

    drop(db_path);
}

fn get_state_for_block(harness: &TestHarness, block_root: Hash256) -> BeaconState<E> {
    let head_block = harness
        .chain
        .store
        .get_blinded_block(&block_root)
        .unwrap()
        .unwrap();
    harness
        .chain
        .get_state(
            &head_block.state_root(),
            Some(head_block.slot()),
            CACHE_STATE_IN_TESTS,
        )
        .unwrap()
        .unwrap()
}

/// Check the invariants that apply to `shuffling_is_compatible`.
fn check_shuffling_compatible(
    harness: &TestHarness,
    head_state: &BeaconState<E>,
    head_block_root: Hash256,
) {
    for maybe_tuple in harness
        .chain
        .rev_iter_block_roots_from(head_block_root)
        .unwrap()
    {
        let (block_root, slot) = maybe_tuple.unwrap();

        // Would an attestation to `block_root` at the current epoch be compatible with the head
        // state's shuffling?
        let current_epoch_shuffling_is_compatible = harness.chain.shuffling_is_compatible(
            &block_root,
            head_state.current_epoch(),
            head_state,
        );

        // Check for consistency with the more expensive shuffling lookup.
        harness
            .chain
            .with_committee_cache(
                block_root,
                head_state.current_epoch(),
                |committee_cache, _| {
                    let state_cache = head_state.committee_cache(RelativeEpoch::Current).unwrap();
                    // We used to check for false negatives here, but had to remove that check
                    // because `shuffling_is_compatible` does not guarantee their absence.
                    //
                    // See: https://github.com/sigp/lighthouse/issues/6269
                    if current_epoch_shuffling_is_compatible {
                        assert_eq!(
                            committee_cache,
                            state_cache.as_ref(),
                            "block at slot {slot}"
                        );
                    }
                    Ok(())
                },
            )
            .unwrap_or_else(|e| {
                // If the lookup fails then the shuffling must be invalid in some way, e.g. the
                // block with `block_root` is from a later epoch than `previous_epoch`.
                assert!(
                    !current_epoch_shuffling_is_compatible,
                    "block at slot {slot} has compatible shuffling at epoch {} \
                     but should be incompatible due to error: {e:?}",
                    head_state.current_epoch()
                );
            });

        // Similarly for the previous epoch
        let previous_epoch_shuffling_is_compatible = harness.chain.shuffling_is_compatible(
            &block_root,
            head_state.previous_epoch(),
            head_state,
        );
        harness
            .chain
            .with_committee_cache(
                block_root,
                head_state.previous_epoch(),
                |committee_cache, _| {
                    let state_cache = head_state.committee_cache(RelativeEpoch::Previous).unwrap();
                    if previous_epoch_shuffling_is_compatible {
                        assert_eq!(committee_cache, state_cache.as_ref());
                    }
                    Ok(())
                },
            )
            .unwrap_or_else(|e| {
                // If the lookup fails then the shuffling must be invalid in some way, e.g. the
                // block with `block_root` is from a later epoch than `previous_epoch`.
                assert!(
                    !previous_epoch_shuffling_is_compatible,
                    "block at slot {slot} has compatible shuffling at epoch {} \
                     but should be incompatible due to error: {e:?}",
                    head_state.previous_epoch()
                );
            });

        // Targeting two epochs before the current epoch should always return false
        if head_state.current_epoch() >= 2 {
            assert!(!harness.chain.shuffling_is_compatible(
                &block_root,
                head_state.current_epoch() - 2,
                head_state
            ));
        }
    }
}

/// These tests check the consistency of:
///
/// - ProtoBlock::proposer_shuffling_root_for_child_block, and
/// - BeaconState::proposer_shuffling_decision_root{_at_epoch}
async fn proposer_shuffling_root_consistency_test(
    spec: ChainSpec,
    parent_slot: u64,
    child_slot: u64,
) {
    let child_slot = Slot::new(child_slot);
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, Default::default(), spec.clone());
    let validators_keypairs =
        types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
    let harness = TestHarness::builder(MinimalEthSpec)
        .spec(spec.into())
        .keypairs(validators_keypairs)
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();
    let spec = &harness.chain.spec;

    // Build chain out to parent block.
    let initial_slots: Vec<Slot> = (1..=parent_slot).map(Into::into).collect();
    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    let (_, _, parent_root, _) = harness
        .add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators)
        .await;

    // Add the child block.
    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    let (_, _, child_root, child_block_state) = harness
        .add_attested_blocks_at_slots(state, state_root, &[child_slot], &all_validators)
        .await;

    let child_block_epoch = child_slot.epoch(E::slots_per_epoch());

    // Load parent block from fork choice.
    let fc_parent = harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&parent_root.into())
        .unwrap();

    // The proposer shuffling decision root computed using fork choice should equal the root
    // computed from the child state.
    let decision_root = fc_parent.proposer_shuffling_root_for_child_block(child_block_epoch, spec);

    assert_eq!(
        decision_root,
        child_block_state
            .proposer_shuffling_decision_root(child_root.into(), spec)
            .unwrap()
    );
    assert_eq!(
        decision_root,
        child_block_state
            .proposer_shuffling_decision_root_at_epoch(child_block_epoch, child_root.into(), spec)
            .unwrap()
    );

    // The passed block root argument should be irrelevant for all blocks except the genesis block.
    assert_eq!(
        decision_root,
        child_block_state
            .proposer_shuffling_decision_root(Hash256::ZERO, spec)
            .unwrap()
    );
    assert_eq!(
        decision_root,
        child_block_state
            .proposer_shuffling_decision_root_at_epoch(child_block_epoch, Hash256::ZERO, spec)
            .unwrap()
    );
}

#[tokio::test]
async fn proposer_shuffling_root_consistency_same_epoch() {
    let spec = test_spec::<E>();
    proposer_shuffling_root_consistency_test(
        spec,
        4 * E::slots_per_epoch(),
        5 * E::slots_per_epoch() - 1,
    )
    .await;
}

#[tokio::test]
async fn proposer_shuffling_root_consistency_next_epoch() {
    let spec = test_spec::<E>();
    proposer_shuffling_root_consistency_test(
        spec,
        4 * E::slots_per_epoch(),
        6 * E::slots_per_epoch() - 1,
    )
    .await;
}

#[tokio::test]
async fn proposer_shuffling_root_consistency_two_epochs() {
    let spec = test_spec::<E>();
    proposer_shuffling_root_consistency_test(
        spec,
        4 * E::slots_per_epoch(),
        7 * E::slots_per_epoch() - 1,
    )
    .await;
}

#[tokio::test]
async fn proposer_shuffling_root_consistency_at_fork_boundary() {
    let mut spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    spec.fulu_fork_epoch = Some(Epoch::new(4));

    // Parent block in epoch prior to Fulu fork epoch, child block in Fulu fork epoch.
    proposer_shuffling_root_consistency_test(
        spec.clone(),
        3 * E::slots_per_epoch(),
        4 * E::slots_per_epoch(),
    )
    .await;

    // Parent block and child block in Fulu fork epoch.
    proposer_shuffling_root_consistency_test(
        spec.clone(),
        4 * E::slots_per_epoch(),
        4 * E::slots_per_epoch() + 1,
    )
    .await;

    // Parent block in Fulu fork epoch and child block in epoch after.
    proposer_shuffling_root_consistency_test(
        spec.clone(),
        4 * E::slots_per_epoch(),
        5 * E::slots_per_epoch(),
    )
    .await;

    // Parent block in epoch prior and child block in epoch after.
    proposer_shuffling_root_consistency_test(
        spec,
        3 * E::slots_per_epoch(),
        5 * E::slots_per_epoch(),
    )
    .await;
}

#[tokio::test]
async fn proposer_shuffling_changing_with_lookahead() {
    let initial_blocks = E::slots_per_epoch() * 4 - 1;

    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, Default::default(), spec.clone());
    let validators_keypairs =
        types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
    let harness = TestHarness::builder(MinimalEthSpec)
        .spec(spec.into())
        .keypairs(validators_keypairs)
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();
    let spec = &harness.chain.spec;

    // Start with some blocks, finishing with one slot before a new epoch.
    harness.advance_slot();
    harness
        .extend_chain(
            initial_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let pre_deposit_state = harness.get_current_state();
    assert_eq!(pre_deposit_state.slot(), initial_blocks);
    let topup_block_slot = Slot::new(initial_blocks + 1);
    let validator_to_topup_index = 1;
    let validator_to_topup = pre_deposit_state
        .get_validator(validator_to_topup_index)
        .unwrap()
        .clone();

    // Craft a block with a deposit request and consolidation.
    // XXX: This is a really nasty way to do this, but we need better test facilities in
    // MockExecutionLayer to address this.
    let deposit_request: DepositRequest = DepositRequest {
        index: pre_deposit_state.eth1_deposit_index(),
        pubkey: validator_to_topup.pubkey,
        withdrawal_credentials: validator_to_topup.withdrawal_credentials,
        amount: 63_000_000_000,
        signature: SignatureBytes::empty(),
    };

    let consolidation_request: ConsolidationRequest = ConsolidationRequest {
        source_address: validator_to_topup
            .get_execution_withdrawal_address(spec)
            .unwrap(),
        source_pubkey: validator_to_topup.pubkey,
        target_pubkey: validator_to_topup.pubkey,
    };

    let execution_requests = ExecutionRequests::<E> {
        deposits: VariableList::new(vec![deposit_request]).unwrap(),
        withdrawals: vec![].into(),
        consolidations: VariableList::new(vec![consolidation_request]).unwrap(),
    };

    let mut block = Box::pin(harness.make_block_with_modifier(
        pre_deposit_state.clone(),
        topup_block_slot,
        |block| *block.body_mut().execution_requests_mut().unwrap() = execution_requests,
    ))
    .await
    .0;

    let Err(BlockError::StateRootMismatch {
        local: true_state_root,
        ..
    }) = harness
        .process_block(topup_block_slot, block.0.canonical_root(), block.clone())
        .await
    else {
        panic!("state root should not match due to pending deposits changes/etc");
    };
    let mut new_block = block.0.message_fulu().unwrap().clone();
    new_block.state_root = true_state_root;
    block.0 = Arc::new(harness.sign_beacon_block(new_block.into(), &pre_deposit_state));

    harness
        .process_block(topup_block_slot, block.0.canonical_root(), block.clone())
        .await
        .unwrap();

    // Advance two epochs to finalize the deposit and process it.
    // Start with just a single epoch advance so we can grab the state one epoch prior to where
    // we end up.
    harness.advance_slot();
    harness
        .extend_chain(
            E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Grab the epoch start state. This is the state from which the proposers at the next epoch were
    // computed.
    let prev_epoch_state = harness.get_current_state();
    assert_eq!(prev_epoch_state.slot() % E::slots_per_epoch(), 0);

    // The deposit should be pending.
    let pending_deposits = prev_epoch_state.pending_deposits().unwrap();
    assert_eq!(pending_deposits.len(), 1, "{pending_deposits:?}");

    // Advance the 2nd epoch to finalize the deposit and process it.
    harness.advance_slot();
    harness
        .extend_chain(
            E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let current_epoch_state = harness.get_current_state();
    assert_eq!(current_epoch_state.slot() % E::slots_per_epoch(), 0);

    // Deposit is processed!
    let pending_deposits = current_epoch_state.pending_deposits().unwrap();
    assert_eq!(pending_deposits.len(), 0, "{pending_deposits:?}");

    let validator = current_epoch_state
        .get_validator(validator_to_topup_index)
        .unwrap();
    assert!(validator.has_compounding_withdrawal_credential(spec));
    assert_eq!(validator.effective_balance, 95_000_000_000);

    // The shuffling for the current epoch from `prev_epoch_state` should match the shuffling
    // for the current epoch from `current_epoch_state` because we should be correctly using the
    // stored lookahead.
    let current_epoch = current_epoch_state.current_epoch();
    let proposer_shuffling = prev_epoch_state
        .get_beacon_proposer_indices(current_epoch, spec)
        .unwrap();

    assert_eq!(
        proposer_shuffling,
        current_epoch_state
            .get_beacon_proposer_indices(current_epoch, spec)
            .unwrap()
    );

    // If we bypass the safety checks in `get_proposer_indices`, we should see that the shuffling
    // differs due to the effective balance change.
    let unsafe_get_proposer_indices = |state: &BeaconState<E>, epoch| -> Vec<usize> {
        let indices = state.get_active_validator_indices(epoch, spec).unwrap();
        let preimage = state.get_seed(epoch, Domain::BeaconProposer, spec).unwrap();
        epoch
            .slot_iter(E::slots_per_epoch())
            .map(|slot| {
                let mut preimage = preimage.to_vec();
                preimage.append(&mut int_to_bytes::int_to_bytes8(slot.as_u64()));
                let seed = ethereum_hashing::hash(&preimage);
                state.compute_proposer_index(&indices, &seed, spec).unwrap()
            })
            .collect()
    };

    // The unsafe function is correct when used with lookahead.
    assert_eq!(
        unsafe_get_proposer_indices(&prev_epoch_state, current_epoch),
        proposer_shuffling
    );

    // Computing the shuffling for current epoch without lookahead is WRONG.
    assert_ne!(
        unsafe_get_proposer_indices(&current_epoch_state, current_epoch),
        proposer_shuffling,
    );
}

#[tokio::test]
async fn proposer_duties_from_head_fulu() {
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());

    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, Default::default(), spec.clone());
    let validators_keypairs =
        types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
    let harness = TestHarness::builder(MinimalEthSpec)
        .spec(spec.into())
        .keypairs(validators_keypairs)
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();
    let spec = &harness.chain.spec;

    let initial_blocks = E::slots_per_epoch() * 3;

    // Build chain out to parent block.
    let initial_slots: Vec<Slot> = (1..=initial_blocks).map(Into::into).collect();
    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    let (_, _, head_block_root, head_state) = harness
        .add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators)
        .await;

    // Compute the proposer duties at the next epoch from the head
    let next_epoch = head_state.next_epoch().unwrap();
    let (_indices, dependent_root, legacy_dependent_root, _, fork) =
        compute_proposer_duties_from_head(next_epoch, &harness.chain).unwrap();

    assert_eq!(
        dependent_root,
        head_state
            .proposer_shuffling_decision_root_at_epoch(next_epoch, head_block_root.into(), spec)
            .unwrap()
    );
    assert_ne!(dependent_root, legacy_dependent_root);
    assert_eq!(legacy_dependent_root, Hash256::from(head_block_root));
    assert_eq!(fork, head_state.fork());
}

/// Test that we can compute the proposer shuffling for the Gloas fork epoch itself using lookahead!
#[tokio::test]
async fn proposer_lookahead_gloas_fork_epoch() {
    let gloas_fork_epoch = Epoch::new(4);
    let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    spec.gloas_fork_epoch = Some(gloas_fork_epoch);

    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, Default::default(), spec.clone());
    let validators_keypairs =
        types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
    let harness = TestHarness::builder(E::default())
        .spec(spec.into())
        .keypairs(validators_keypairs)
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();
    let spec = &harness.chain.spec;

    let initial_blocks = (gloas_fork_epoch - 1)
        .start_slot(E::slots_per_epoch())
        .as_u64();

    // Build chain out to parent block.
    let initial_slots: Vec<Slot> = (1..=initial_blocks).map(Into::into).collect();
    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    let (_, _, head_block_root, mut head_state) = harness
        .add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators)
        .await;
    let head_state_root = head_state.canonical_root().unwrap();

    // Check that we have access to the next epoch shuffling according to
    // `ensure_state_can_determine_proposers_for_epoch`.
    ensure_state_can_determine_proposers_for_epoch(
        &mut head_state,
        head_state_root,
        gloas_fork_epoch,
        spec,
    )
    .unwrap();
    assert_eq!(head_state.current_epoch(), gloas_fork_epoch - 1);

    // Compute the proposer duties at the fork epoch from the head.
    let (indices, dependent_root, legacy_dependent_root, _, fork) =
        compute_proposer_duties_from_head(gloas_fork_epoch, &harness.chain).unwrap();

    assert_eq!(
        dependent_root,
        head_state
            .proposer_shuffling_decision_root_at_epoch(
                gloas_fork_epoch,
                head_block_root.into(),
                spec
            )
            .unwrap()
    );
    assert_ne!(dependent_root, legacy_dependent_root);
    assert_ne!(fork, head_state.fork());
    assert_eq!(fork, spec.fork_at_epoch(gloas_fork_epoch));

    // Build a block in the Gloas fork epoch and assert that the shuffling does not change.
    let gloas_slots = vec![gloas_fork_epoch.start_slot(E::slots_per_epoch())];
    let (_, _, _, _) = harness
        .add_attested_blocks_at_slots(head_state, head_state_root, &gloas_slots, &all_validators)
        .await;

    let (no_lookahead_indices, no_lookahead_dependent_root, _, _, no_lookahead_fork) =
        compute_proposer_duties_from_head(gloas_fork_epoch, &harness.chain).unwrap();

    assert_eq!(no_lookahead_indices, indices);
    assert_eq!(no_lookahead_dependent_root, dependent_root);
    assert_eq!(no_lookahead_fork, fork);
}

// Ensure blocks from abandoned forks are pruned from the Hot DB
#[tokio::test]
async fn prunes_abandoned_fork_between_two_finalized_checkpoints() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let slots_per_epoch = rig.slots_per_epoch();
    let (mut state, state_root) = rig.get_current_state_and_root();

    let canonical_chain_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_chain_blocks_pre_finalization, _, _, new_state) = rig
        .add_attested_blocks_at_slots(
            state,
            state_root,
            &canonical_chain_slots,
            &honest_validators,
        )
        .await;
    state = new_state;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    let stray_slots: Vec<Slot> = (canonical_chain_slot + 1..rig.epoch_start_slot(2))
        .map(Slot::new)
        .collect();
    let (current_state, current_state_root) = rig.get_current_state_and_root();
    let (stray_blocks, stray_states, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            current_state,
            current_state_root,
            &stray_slots,
            &adversarial_validators,
        )
        .await;

    // Precondition: Ensure all stray_blocks blocks are still known
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {});

    rig.assert_knows_head(stray_head.into());

    // Trigger finalization
    let finalization_slots: Vec<Slot> = ((canonical_chain_slot + 1)
        ..=(canonical_chain_slot + slots_per_epoch * 5))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (canonical_chain_blocks_post_finalization, _, _, _) = rig
        .add_attested_blocks_at_slots(state, state_root, &finalization_slots, &honest_validators)
        .await;

    // Postcondition: New blocks got finalized
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_chain_blocks_pre_finalization[&rig.epoch_start_slot(1).into()],
            canonical_chain_blocks_post_finalization[&rig.epoch_start_slot(2).into()],
        },
    );

    // Postcondition: Ensure all stray_blocks blocks have been pruned
    for &block_hash in stray_blocks.values() {
        assert!(
            !rig.block_exists(block_hash),
            "abandoned block {block_hash:?} should have been pruned",
        );
        assert!(
            !rig.chain.store.blobs_exist(&block_hash.into()).unwrap(),
            "blobs for abandoned block {block_hash:?} should have been pruned"
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(!rig.knows_head(&stray_head));
}

#[tokio::test]
async fn pruning_does_not_touch_abandoned_block_shared_with_canonical_chain() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let slots_per_epoch = rig.slots_per_epoch();
    let (state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch
    let canonical_chain_slots_zeroth_epoch: Vec<Slot> =
        (1..rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (_, _, _, mut state) = rig
        .add_attested_blocks_at_slots(
            state,
            state_root,
            &canonical_chain_slots_zeroth_epoch,
            &honest_validators,
        )
        .await;

    // Fill up 1st epoch
    let canonical_chain_slots_first_epoch: Vec<Slot> = (rig.epoch_start_slot(1)
        ..=rig.epoch_start_slot(1) + 1)
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (canonical_chain_blocks_first_epoch, _, shared_head, mut state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_chain_slots_first_epoch,
            &honest_validators,
        )
        .await;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    let stray_chain_slots_first_epoch: Vec<Slot> = (rig.epoch_start_slot(1) + 2
        ..=rig.epoch_start_slot(1) + 2)
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &stray_chain_slots_first_epoch,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    let chain_dump = rig.chain.chain_dump().unwrap();
    assert_eq!(
        get_finalized_epoch_boundary_blocks(&chain_dump),
        vec![Hash256::zero().into()].into_iter().collect(),
    );

    assert!(get_blocks(&chain_dump).contains(&shared_head));

    // Trigger finalization
    let finalization_slots: Vec<Slot> = ((canonical_chain_slot + 1)
        ..=(canonical_chain_slot + slots_per_epoch * 5))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (canonical_chain_blocks, _, _, _) = rig
        .add_attested_blocks_at_slots(state, state_root, &finalization_slots, &honest_validators)
        .await;

    // Postconditions
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_chain_blocks_first_epoch[&rig.epoch_start_slot(1).into()],
            canonical_chain_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    for &block_hash in stray_blocks.values() {
        assert!(
            !rig.block_exists(block_hash),
            "stray block {} should have been pruned",
            block_hash,
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(!rig.knows_head(&stray_head));
    let chain_dump = rig.chain.chain_dump().unwrap();
    assert!(get_blocks(&chain_dump).contains(&shared_head));
}

#[tokio::test]
async fn pruning_does_not_touch_blocks_prior_to_finalization() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let slots_per_epoch = rig.slots_per_epoch();
    let (mut state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch with canonical chain blocks
    let zeroth_epoch_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_chain_blocks, _, _, new_state) = rig
        .add_attested_blocks_at_slots(state, state_root, &zeroth_epoch_slots, &honest_validators)
        .await;
    state = new_state;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    // Fill up 1st epoch.  Contains a fork.
    let first_epoch_slots: Vec<Slot> = ((rig.epoch_start_slot(1) + 1)..(rig.epoch_start_slot(2)))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &first_epoch_slots,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {});

    // Trigger finalization
    let slots: Vec<Slot> = ((canonical_chain_slot + 1)
        ..=(canonical_chain_slot + slots_per_epoch * 4))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (_, _, _, _) = rig
        .add_attested_blocks_at_slots(state, state_root, &slots, &honest_validators)
        .await;

    // Postconditions
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {canonical_chain_blocks[&rig.epoch_start_slot(1).into()]},
    );

    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    rig.assert_knows_head(stray_head.into());
}

#[tokio::test]
async fn prunes_fork_growing_past_youngest_finalized_checkpoint() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let (state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch with canonical chain blocks
    let zeroth_epoch_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut state) = rig
        .add_attested_blocks_at_slots(state, state_root, &zeroth_epoch_slots, &honest_validators)
        .await;

    // Fill up 1st epoch.  Contains a fork.
    let slots_first_epoch: Vec<Slot> = (rig.epoch_start_slot(1) + 1..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks_first_epoch, stray_states_first_epoch, _, mut stray_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &slots_first_epoch,
            &adversarial_validators,
        )
        .await;
    let (canonical_blocks_first_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(state, state_root, &slots_first_epoch, &honest_validators)
        .await;

    // Fill up 2nd epoch.  Extends both the canonical chain and the fork.
    let stray_slots_second_epoch: Vec<Slot> = (rig.epoch_start_slot(2)
        ..=rig.epoch_start_slot(2) + 1)
        .map(Into::into)
        .collect();
    let stray_state_root = stray_state.update_tree_hash_cache().unwrap();
    let (stray_blocks_second_epoch, stray_states_second_epoch, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            stray_state,
            stray_state_root,
            &stray_slots_second_epoch,
            &adversarial_validators,
        )
        .await;

    // Precondition: Ensure all stray_blocks blocks are still known
    let stray_blocks: HashMap<Slot, SignedBeaconBlockHash> = stray_blocks_first_epoch
        .into_iter()
        .chain(stray_blocks_second_epoch.into_iter())
        .collect();

    let stray_states: HashMap<Slot, BeaconStateHash> = stray_states_first_epoch
        .into_iter()
        .chain(stray_states_second_epoch.into_iter())
        .collect();

    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    // Precondition: Nothing is finalized yet
    assert_eq!(rig.get_finalized_checkpoints(), hashset! {},);

    rig.assert_knows_head(stray_head.into());

    // Trigger finalization
    let canonical_slots: Vec<Slot> = (rig.epoch_start_slot(2)..=rig.epoch_start_slot(6))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (canonical_blocks, _, _, _) = Box::pin(rig.add_attested_blocks_at_slots(
        canonical_state,
        canonical_state_root,
        &canonical_slots,
        &honest_validators,
    ))
    .await;

    // Postconditions
    let canonical_blocks: HashMap<Slot, SignedBeaconBlockHash> = canonical_blocks_zeroth_epoch
        .into_iter()
        .chain(canonical_blocks_first_epoch.into_iter())
        .chain(canonical_blocks.into_iter())
        .collect();

    // Postcondition: New blocks got finalized
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_blocks[&rig.epoch_start_slot(1).into()],
            canonical_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    // Postcondition: Ensure all stray_blocks blocks have been pruned
    for &block_hash in stray_blocks.values() {
        assert!(
            !rig.block_exists(block_hash),
            "abandoned block {} should have been pruned",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(!rig.knows_head(&stray_head));
}

// This is to check if state outside of normal block processing are pruned correctly.
#[tokio::test]
async fn prunes_skipped_slots_states() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let (state, state_root) = rig.get_current_state_and_root();

    let canonical_slots_zeroth_epoch: Vec<Slot> =
        (1..=rig.epoch_start_slot(1)).map(Into::into).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_slots_zeroth_epoch,
            &honest_validators,
        )
        .await;

    let skipped_slot: Slot = (rig.epoch_start_slot(1) + 1).into();

    let stray_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, _, stray_state) = rig
        .add_attested_blocks_at_slots(
            canonical_state.clone(),
            canonical_state_root,
            &stray_slots,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {},);

    // Make sure slots were skipped
    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash = (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            rig.hot_state_exists(state_hash),
            "skipped slot state {} should be still present",
            state_hash
        );
    }

    // Trigger finalization
    let canonical_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(7))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (canonical_blocks_post_finalization, _, _, _) = rig
        .add_attested_blocks_at_slots(
            canonical_state,
            canonical_state_root,
            &canonical_slots,
            &honest_validators,
        )
        .await;

    // Postconditions
    let canonical_blocks: HashMap<Slot, SignedBeaconBlockHash> = canonical_blocks_zeroth_epoch
        .into_iter()
        .chain(canonical_blocks_post_finalization.into_iter())
        .collect();
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_blocks[&rig.epoch_start_slot(1).into()],
            canonical_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash: BeaconStateHash =
            (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            !rig.hot_state_exists(state_hash),
            "skipped slot {} state {} should have been pruned",
            skipped_slot,
            state_hash
        );
    }
}

// This is to check if state outside of normal block processing are pruned correctly.
#[tokio::test]
async fn finalizes_non_epoch_start_slot() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let (state, state_root) = rig.get_current_state_and_root();

    let canonical_slots_zeroth_epoch: Vec<Slot> =
        (1..rig.epoch_start_slot(1)).map(Into::into).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_slots_zeroth_epoch,
            &honest_validators,
        )
        .await;

    let skipped_slot: Slot = rig.epoch_start_slot(1).into();

    let stray_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, _, stray_state) = rig
        .add_attested_blocks_at_slots(
            canonical_state.clone(),
            canonical_state_root,
            &stray_slots,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {});

    // Make sure slots were skipped
    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash = (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            rig.hot_state_exists(state_hash),
            "skipped slot state {} should be still present",
            state_hash
        );
    }

    // Trigger finalization
    let canonical_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(7))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (canonical_blocks_post_finalization, _, _, _) = rig
        .add_attested_blocks_at_slots(
            canonical_state,
            canonical_state_root,
            &canonical_slots,
            &honest_validators,
        )
        .await;

    // Postconditions
    let canonical_blocks: HashMap<Slot, SignedBeaconBlockHash> = canonical_blocks_zeroth_epoch
        .into_iter()
        .chain(canonical_blocks_post_finalization.into_iter())
        .collect();
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_blocks[&(rig.epoch_start_slot(1)-1).into()],
            canonical_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash: BeaconStateHash =
            (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            !rig.hot_state_exists(state_hash),
            "skipped slot {} state {} should have been pruned",
            skipped_slot,
            state_hash
        );
    }
}

fn check_all_blocks_exist<'a>(
    harness: &TestHarness,
    blocks: impl Iterator<Item = &'a SignedBeaconBlockHash>,
) {
    for &block_hash in blocks {
        let block = harness.chain.get_blinded_block(&block_hash.into()).unwrap();
        assert!(
            block.is_some(),
            "expected block {:?} to be in DB",
            block_hash
        );
    }
}

fn check_all_states_exist<'a>(
    harness: &TestHarness,
    states: impl Iterator<Item = &'a BeaconStateHash>,
) {
    for &state_hash in states {
        let state = harness
            .chain
            .get_state(&state_hash.into(), None, CACHE_STATE_IN_TESTS)
            .unwrap();
        assert!(
            state.is_some(),
            "expected state {:?} to be in DB",
            state_hash,
        );
    }
}

// Check that none of the given states exist in the database.
fn check_no_states_exist<'a>(
    harness: &TestHarness,
    states: impl Iterator<Item = &'a BeaconStateHash>,
) {
    for &state_root in states {
        assert!(
            harness
                .chain
                .get_state(&state_root.into(), None, CACHE_STATE_IN_TESTS)
                .unwrap()
                .is_none(),
            "state {:?} should not be in the DB",
            state_root
        );
    }
}

// Check that none of the given blocks exist in the database.
fn check_no_blocks_exist<'a>(
    harness: &TestHarness,
    blocks: impl Iterator<Item = &'a SignedBeaconBlockHash>,
) {
    for &block_hash in blocks {
        let block = harness.chain.get_blinded_block(&block_hash.into()).unwrap();
        assert!(
            block.is_none(),
            "did not expect block {:?} to be in the DB",
            block_hash
        );
        assert!(
            !harness.chain.store.blobs_exist(&block_hash.into()).unwrap(),
            "blobs for abandoned block {block_hash:?} should have been pruned"
        );
    }
}

#[tokio::test]
async fn prune_single_block_fork() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(3 * slots_per_epoch, 1, slots_per_epoch, 0, 1).await;
}

#[tokio::test]
async fn prune_single_block_long_skip() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(
        2 * slots_per_epoch,
        1,
        2 * slots_per_epoch,
        2 * slots_per_epoch,
        1,
    )
    .await;
}

#[tokio::test]
async fn prune_shared_skip_states_mid_epoch() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(
        slots_per_epoch + slots_per_epoch / 2,
        1,
        slots_per_epoch,
        2,
        slots_per_epoch - 1,
    )
    .await;
}

#[tokio::test]
async fn prune_shared_skip_states_epoch_boundaries() {
    let slots_per_epoch = E::slots_per_epoch();
    Box::pin(pruning_test(
        slots_per_epoch - 1,
        1,
        slots_per_epoch,
        2,
        slots_per_epoch,
    ))
    .await;
    Box::pin(pruning_test(
        slots_per_epoch - 1,
        2,
        slots_per_epoch,
        1,
        slots_per_epoch,
    ))
    .await;
    Box::pin(pruning_test(
        2 * slots_per_epoch + slots_per_epoch / 2,
        slots_per_epoch / 2,
        slots_per_epoch,
        slots_per_epoch / 2 + 1,
        slots_per_epoch,
    ))
    .await;
    Box::pin(pruning_test(
        2 * slots_per_epoch + slots_per_epoch / 2,
        slots_per_epoch / 2,
        slots_per_epoch,
        slots_per_epoch / 2 + 1,
        slots_per_epoch,
    ))
    .await;
    Box::pin(pruning_test(
        2 * slots_per_epoch - 1,
        slots_per_epoch,
        1,
        0,
        2 * slots_per_epoch,
    ))
    .await;
}

/// Generic harness for pruning tests.
async fn pruning_test(
    // Number of blocks to start the chain with before forking.
    num_initial_blocks: u64,
    // Number of skip slots on the main chain after the initial blocks.
    num_canonical_skips: u64,
    // Number of blocks on the main chain after the skip, but before the finalisation-triggering
    // blocks.
    num_canonical_middle_blocks: u64,
    // Number of skip slots on the fork chain after the initial blocks.
    num_fork_skips: u64,
    // Number of blocks on the fork chain after the skips.
    num_fork_blocks: u64,
) {
    const VALIDATOR_COUNT: usize = 24;
    const VALIDATOR_SUPERMAJORITY: usize = (VALIDATOR_COUNT / 3) * 2;
    const HONEST_VALIDATOR_COUNT: usize = VALIDATOR_SUPERMAJORITY;

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let faulty_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();

    let slots = |start: Slot, num_blocks: u64| -> Vec<Slot> {
        (start.as_u64()..start.as_u64() + num_blocks)
            .map(Slot::new)
            .collect()
    };

    let start_slot = Slot::new(1);
    let divergence_slot = start_slot + num_initial_blocks;
    let (state, state_root) = harness.get_current_state_and_root();
    let (_, _, _, divergence_state) = harness
        .add_attested_blocks_at_slots(
            state,
            state_root,
            &slots(start_slot, num_initial_blocks)[..],
            &honest_validators,
        )
        .await;

    let mut chains = harness
        .add_blocks_on_multiple_chains(vec![
            // Canonical chain
            (
                divergence_state.clone(),
                slots(
                    divergence_slot + num_canonical_skips,
                    num_canonical_middle_blocks,
                ),
                honest_validators.clone(),
            ),
            // Fork chain
            (
                divergence_state.clone(),
                slots(divergence_slot + num_fork_skips, num_fork_blocks),
                faulty_validators,
            ),
        ])
        .await;
    let (_, _, _, mut canonical_state) = chains.remove(0);
    let (stray_blocks, stray_states, _, stray_head_state) = chains.remove(0);

    let stray_head_slot = divergence_slot + num_fork_skips + num_fork_blocks - 1;
    let stray_head_state_root = stray_states[&stray_head_slot];
    let stray_states = harness
        .chain
        .rev_iter_state_roots_from(stray_head_state_root.into(), &stray_head_state)
        .map(Result::unwrap)
        .map(|(state_root, _)| state_root.into())
        .collect::<HashSet<_>>();

    check_all_blocks_exist(&harness, stray_blocks.values());
    check_all_states_exist(&harness, stray_states.iter());

    let chain_dump = harness.chain.chain_dump().unwrap();
    assert_eq!(
        get_finalized_epoch_boundary_blocks(&chain_dump),
        vec![Hash256::zero().into()].into_iter().collect(),
    );

    // Trigger finalization
    let num_finalization_blocks = 4 * E::slots_per_epoch();
    let canonical_slot = divergence_slot + num_canonical_skips + num_canonical_middle_blocks;
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    harness
        .add_attested_blocks_at_slots(
            canonical_state,
            canonical_state_root,
            &slots(canonical_slot, num_finalization_blocks),
            &honest_validators,
        )
        .await;

    // Check that finalization has advanced past the divergence slot.
    assert!(
        harness
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch())
            > divergence_slot
    );
    check_chain_dump(
        &harness,
        num_initial_blocks + num_canonical_middle_blocks + num_finalization_blocks + 1,
    );

    let all_canonical_states = harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
        .map(|(state_root, _)| state_root.into())
        .collect::<HashSet<BeaconStateHash>>();

    check_all_states_exist(&harness, all_canonical_states.iter());
    check_no_states_exist(&harness, stray_states.difference(&all_canonical_states));
    check_no_blocks_exist(&harness, stray_blocks.values());
}

#[tokio::test]
async fn garbage_collect_temp_states_from_failed_block_on_finalization() {
    let db_path = tempdir().unwrap();

    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let slots_per_epoch = E::slots_per_epoch();

    let mut genesis_state = harness.get_current_state();
    let genesis_state_root = genesis_state.update_tree_hash_cache().unwrap();
    let block_slot = Slot::new(2 * slots_per_epoch);
    let ((signed_block, _), state) = harness.make_block(genesis_state, block_slot).await;

    let (mut block, _) = (*signed_block).clone().deconstruct();
    let bad_block_parent_root = block.parent_root();

    // Mutate the block to make it invalid, and re-sign it.
    *block.state_root_mut() = Hash256::repeat_byte(0xff);
    let proposer_index = block.proposer_index() as usize;
    let block = Arc::new(block.sign(
        &harness.validator_keypairs[proposer_index].sk,
        &state.fork(),
        state.genesis_validators_root(),
        &harness.spec,
    ));

    // The block should be rejected, but should store a bunch of temporary states.
    harness.set_current_slot(block_slot);
    harness
        .process_block_result((block, None))
        .await
        .unwrap_err();

    // The bad block parent root is the genesis block root. There's `block_slot - 1` temporary
    // states to remove + the genesis state = block_slot.
    assert_eq!(
        get_states_descendant_of_block(&store, bad_block_parent_root).len(),
        block_slot.as_usize(),
    );

    // Finalize the chain without the block, which should result in pruning of all temporary states.
    let blocks_required_to_finalize = 3 * slots_per_epoch;
    harness.advance_slot();
    harness
        .extend_chain(
            blocks_required_to_finalize as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Check that the finalization migration ran.
    assert_ne!(store.get_split_slot(), 0);

    // Check that temporary states have been pruned.
    assert_eq!(
        get_states_descendant_of_block(&store, bad_block_parent_root),
        // The genesis state is kept to support the HDiff grid
        vec![(genesis_state_root, Slot::new(0))],
        "get_states_descendant_of_block({bad_block_parent_root:?})"
    );
}

#[tokio::test]
async fn weak_subjectivity_sync_easy() {
    let num_initial_slots = E::slots_per_epoch() * 11;
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 9);
    let slots = (1..num_initial_slots).map(Slot::new).collect();
    weak_subjectivity_sync_test(slots, checkpoint_slot, None).await
}

#[tokio::test]
async fn weak_subjectivity_sync_single_block_batches() {
    let num_initial_slots = E::slots_per_epoch() * 11;
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 9);
    let slots = (1..num_initial_slots).map(Slot::new).collect();
    weak_subjectivity_sync_test(slots, checkpoint_slot, Some(1)).await
}

#[tokio::test]
async fn weak_subjectivity_sync_unaligned_advanced_checkpoint() {
    let num_initial_slots = E::slots_per_epoch() * 11;
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 9);
    let slots = (1..num_initial_slots)
        .map(Slot::new)
        .filter(|&slot| {
            // Skip 3 slots leading up to the checkpoint slot.
            slot <= checkpoint_slot - 3 || slot > checkpoint_slot
        })
        .collect();
    weak_subjectivity_sync_test(slots, checkpoint_slot, None).await
}

#[tokio::test]
async fn weak_subjectivity_sync_unaligned_unadvanced_checkpoint() {
    let num_initial_slots = E::slots_per_epoch() * 11;
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 9 - 3);
    let slots = (1..num_initial_slots)
        .map(Slot::new)
        .filter(|&slot| {
            // Skip 3 slots after the checkpoint slot.
            slot <= checkpoint_slot || slot > checkpoint_slot + 3
        })
        .collect();
    weak_subjectivity_sync_test(slots, checkpoint_slot, None).await
}

// Regression test for https://github.com/sigp/lighthouse/issues/4817
// Skip 3 slots immediately after genesis, creating a gap between the genesis block and the first
// real block.
#[tokio::test]
async fn weak_subjectivity_sync_skips_at_genesis() {
    let start_slot = 4;
    let end_slot = E::slots_per_epoch() * 4;
    let slots = (start_slot..end_slot).map(Slot::new).collect();
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 2);
    weak_subjectivity_sync_test(slots, checkpoint_slot, None).await
}

// Checkpoint sync from the genesis state.
//
// This is a regression test for a bug we had involving the storage of the genesis state in the hot
// DB.
#[tokio::test]
async fn weak_subjectivity_sync_from_genesis() {
    let start_slot = 1;
    let end_slot = E::slots_per_epoch() * 2;
    let slots = (start_slot..end_slot).map(Slot::new).collect();
    let checkpoint_slot = Slot::new(0);
    weak_subjectivity_sync_test(slots, checkpoint_slot, None).await
}

async fn weak_subjectivity_sync_test(
    slots: Vec<Slot>,
    checkpoint_slot: Slot,
    backfill_batch_size: Option<usize>,
) {
    // Build an initial chain on one harness, representing a synced node with full history.
    let num_final_blocks = E::slots_per_epoch() * 2;

    let temp1 = tempdir().unwrap();
    let full_store = get_store(&temp1);

    // TODO(das): Run a supernode so the node has full blobs stored.
    // This may not be required in the future if we end up implementing downloading checkpoint
    // blobs from p2p peers:
    // https://github.com/sigp/lighthouse/issues/6837
    let harness = get_harness_import_all_data_columns(full_store.clone(), LOW_VALIDATOR_COUNT);

    let all_validators = (0..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();

    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    harness
        .add_attested_blocks_at_slots(
            genesis_state.clone(),
            genesis_state_root,
            &slots,
            &all_validators,
        )
        .await;

    let wss_block_root = harness
        .chain
        .block_root_at_slot(checkpoint_slot, WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();
    let wss_state_root = harness
        .chain
        .state_root_at_slot(checkpoint_slot)
        .unwrap()
        .unwrap();

    let wss_block = harness
        .chain
        .store
        .get_full_block(&wss_block_root)
        .unwrap()
        .unwrap();
    let wss_blobs_opt = harness
        .chain
        .get_or_reconstruct_blobs(&wss_block_root)
        .unwrap();
    let wss_state = full_store
        .get_state(&wss_state_root, Some(checkpoint_slot), CACHE_STATE_IN_TESTS)
        .unwrap()
        .unwrap();
    let wss_state_slot = wss_state.slot();
    let wss_block_slot = wss_block.slot();

    // Add more blocks that advance finalization further.
    harness.advance_slot();
    harness
        .extend_chain(
            num_final_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (shutdown_tx, _shutdown_rx) = futures::channel::mpsc::channel(1);

    let temp2 = tempdir().unwrap();
    let store = get_store(&temp2);
    let spec = test_spec::<E>();
    let seconds_per_slot = spec.seconds_per_slot;

    let kzg = get_kzg(&spec);

    let mock = mock_execution_layer_from_parts(
        harness.spec.clone(),
        harness.runtime.task_executor.clone(),
    );

    // Initialise a new beacon chain from the finalized checkpoint.
    // The slot clock must be set to a time ahead of the checkpoint state.
    let slot_clock = TestingSlotClock::new(
        Slot::new(0),
        Duration::from_secs(harness.chain.genesis_time),
        Duration::from_secs(seconds_per_slot),
    );
    slot_clock.set_slot(harness.get_current_slot().as_u64());

    let chain_config = ChainConfig {
        // Set reconstruct_historic_states to true from the start in the genesis case. This makes
        // some of the later checks more uniform across the genesis/non-genesis cases.
        reconstruct_historic_states: checkpoint_slot == 0,
        ..ChainConfig::default()
    };

    let beacon_chain = BeaconChainBuilder::<DiskHarnessType<E>>::new(MinimalEthSpec, kzg)
        .chain_config(chain_config)
        .store(store.clone())
        .custom_spec(test_spec::<E>().into())
        .task_executor(harness.chain.task_executor.clone())
        .weak_subjectivity_state(
            wss_state,
            wss_block.clone(),
            wss_blobs_opt.clone(),
            genesis_state,
        )
        .unwrap()
        .store_migrator_config(MigratorConfig::default().blocking())
        .slot_clock(slot_clock)
        .shutdown_sender(shutdown_tx)
        .event_handler(Some(ServerSentEventHandler::new_with_capacity(1)))
        .execution_layer(Some(mock.el))
        .ordered_custody_column_indices(generate_data_column_indices_rand_order::<E>())
        .rng(Box::new(StdRng::seed_from_u64(42)))
        .build()
        .expect("should build");

    let beacon_chain = Arc::new(beacon_chain);
    let wss_block_root = wss_block.canonical_root();
    let store_wss_block = harness
        .chain
        .get_block(&wss_block_root)
        .await
        .unwrap()
        .unwrap();
    // This test may break in the future if we no longer store the full checkpoint data columns.
    let store_wss_blobs_opt = beacon_chain
        .get_or_reconstruct_blobs(&wss_block_root)
        .unwrap();

    assert_eq!(store_wss_block, wss_block);
    // TODO(fulu): Remove this condition once #6760 (PeerDAS checkpoint sync) is merged.
    if !beacon_chain.spec.is_peer_das_scheduled() {
        assert_eq!(store_wss_blobs_opt, wss_blobs_opt);
    }

    // Apply blocks forward to reach head.
    let chain_dump = harness.chain.chain_dump().unwrap();
    let new_blocks = chain_dump
        .iter()
        .filter(|snapshot| snapshot.beacon_block.slot() > checkpoint_slot);

    for snapshot in new_blocks {
        let block_root = snapshot.beacon_block_root;
        let full_block = harness
            .chain
            .get_block(&snapshot.beacon_block_root)
            .await
            .unwrap()
            .unwrap();

        let slot = full_block.slot();
        let full_block_root = full_block.canonical_root();
        let state_root = full_block.state_root();

        info!(block_root = ?full_block_root, ?state_root, %slot, "Importing block from chain dump");
        beacon_chain.slot_clock.set_slot(slot.as_u64());
        beacon_chain
            .process_block(
                full_block_root,
                harness.build_rpc_block_from_store_blobs(Some(block_root), Arc::new(full_block)),
                NotifyExecutionLayer::Yes,
                BlockImportSource::Lookup,
                || Ok(()),
            )
            .await
            .unwrap();
        beacon_chain.recompute_head_at_current_slot().await;

        // Check that the new block's state can be loaded correctly.
        let mut state = beacon_chain
            .store
            .get_state(&state_root, Some(slot), CACHE_STATE_IN_TESTS)
            .unwrap()
            .unwrap();
        assert_eq!(state.update_tree_hash_cache().unwrap(), state_root);
    }

    if checkpoint_slot != 0 {
        // Forwards iterator from 0 should fail as we lack blocks (unless checkpoint slot is 0).
        assert!(matches!(
            beacon_chain.forwards_iter_block_roots(Slot::new(0)),
            Err(BeaconChainError::HistoricalBlockOutOfRange { .. })
        ));
    } else {
        assert_eq!(
            beacon_chain
                .forwards_iter_block_roots(Slot::new(0))
                .unwrap()
                .next()
                .unwrap()
                .unwrap(),
            (wss_block_root, Slot::new(0))
        );
    }

    // The checks in this block only make sense if some data is missing as a result of the
    // checkpoint sync, i.e. if we are not just checkpoint syncing from genesis.
    if checkpoint_slot != 0 {
        // Simulate processing of a `StatusMessage` with an older finalized epoch by calling
        // `block_root_at_slot` with an old slot for which we don't know the block root. It should
        // return `None` rather than erroring.
        assert_eq!(
            beacon_chain
                .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
                .unwrap(),
            None
        );

        // Simulate querying the API for a historic state that is unknown. It should also return
        // `None` rather than erroring.
        assert_eq!(beacon_chain.state_root_at_slot(Slot::new(1)).unwrap(), None);

        // Supply blocks backwards to reach genesis. Omit the genesis block to check genesis handling.
        let historical_blocks = chain_dump[..wss_block.slot().as_usize()]
            .iter()
            .filter(|s| s.beacon_block.slot() != 0)
            .map(|s| s.beacon_block.clone())
            .collect::<Vec<_>>();

        let mut available_blocks = vec![];
        for blinded in historical_blocks {
            let block_root = blinded.canonical_root();
            let full_block = harness
                .chain
                .get_block(&block_root)
                .await
                .expect("should get block")
                .expect("should get block");

            if let MaybeAvailableBlock::Available(block) = harness
                .chain
                .data_availability_checker
                .verify_kzg_for_rpc_block(
                    harness
                        .build_rpc_block_from_store_blobs(Some(block_root), Arc::new(full_block)),
                )
                .expect("should verify kzg")
            {
                available_blocks.push(block);
            }
        }

        // Corrupt the signature on the 1st block to ensure that the backfill processor is checking
        // signatures correctly. Regression test for https://github.com/sigp/lighthouse/pull/5120.
        let mut batch_with_invalid_first_block =
            available_blocks.iter().map(clone_block).collect::<Vec<_>>();
        batch_with_invalid_first_block[0] = {
            let (block_root, block, data) = clone_block(&available_blocks[0]).deconstruct();
            let mut corrupt_block = (*block).clone();
            *corrupt_block.signature_mut() = Signature::empty();
            AvailableBlock::__new_for_testing(
                block_root,
                Arc::new(corrupt_block),
                data,
                Arc::new(spec),
            )
        };

        // Importing the invalid batch should error.
        assert!(matches!(
            beacon_chain
                .import_historical_block_batch(batch_with_invalid_first_block)
                .unwrap_err(),
            HistoricalBlockError::InvalidSignature
        ));
        assert_eq!(beacon_chain.store.get_oldest_block_slot(), wss_block.slot());

        let batch_size = backfill_batch_size.unwrap_or(available_blocks.len());

        for batch in available_blocks.rchunks(batch_size) {
            let available_blocks_slots = batch
                .iter()
                .map(|block| (block.block().slot(), block.block().canonical_root()))
                .collect::<Vec<_>>();
            info!(
                ?available_blocks_slots,
                "wss_block_slot" = wss_block.slot().as_usize(),
                "Importing historical block batch"
            );

            // Importing the batch with valid signatures should succeed.
            let available_blocks_batch1 = batch.iter().map(clone_block).collect::<Vec<_>>();
            beacon_chain
                .import_historical_block_batch(available_blocks_batch1)
                .unwrap();

            // We should be able to load the block root at the `oldest_block_slot`.
            //
            // This is a regression test for: https://github.com/sigp/lighthouse/issues/7690
            let oldest_block_imported = &batch[0];
            let (oldest_block_slot, oldest_block_root) =
                if oldest_block_imported.block().parent_root() == beacon_chain.genesis_block_root {
                    (Slot::new(0), beacon_chain.genesis_block_root)
                } else {
                    available_blocks_slots[0]
                };
            assert_eq!(
                beacon_chain.store.get_oldest_block_slot(),
                oldest_block_slot
            );
            assert_eq!(
                beacon_chain
                    .block_root_at_slot(oldest_block_slot, WhenSlotSkipped::None)
                    .unwrap()
                    .unwrap(),
                oldest_block_root
            );

            // Resupplying the blocks should not fail, they can be safely ignored.
            let available_blocks_batch2 = batch.iter().map(clone_block).collect::<Vec<_>>();
            beacon_chain
                .import_historical_block_batch(available_blocks_batch2)
                .unwrap();
        }
    }
    assert_eq!(beacon_chain.store.get_oldest_block_slot(), 0);

    // Sanity check for non-aligned WSS starts, to make sure the WSS block is persisted properly
    if wss_block_slot != wss_state_slot {
        let new_node_block_root_at_wss_block = beacon_chain
            .store
            .get_cold_block_root(wss_block_slot)
            .unwrap()
            .unwrap();
        info!(?new_node_block_root_at_wss_block, %wss_block_slot);
        assert_eq!(new_node_block_root_at_wss_block, wss_block.canonical_root());
    }

    // The forwards iterator should now match the original chain
    let forwards = beacon_chain
        .forwards_iter_block_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    let expected = harness
        .chain
        .forwards_iter_block_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(forwards, expected);

    // All blocks can be loaded.
    let mut prev_block_root = Hash256::zero();
    for (block_root, slot) in beacon_chain
        .forwards_iter_block_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
    {
        let block = store.get_blinded_block(&block_root).unwrap().unwrap();
        if block_root != prev_block_root {
            assert_eq!(block.slot(), slot);
        }

        // Prune_payloads is set to false in the default config, so the payload should exist
        if block.message().execution_payload().is_ok() {
            assert!(
                beacon_chain
                    .store
                    .execution_payload_exists(&block_root)
                    .unwrap(),
            );
        }

        prev_block_root = block_root;
    }

    // All states from the oldest state slot can be loaded.
    let (_, oldest_state_slot) = store.get_historic_state_limits();
    for (state_root, slot) in beacon_chain
        .forwards_iter_state_roots(oldest_state_slot)
        .unwrap()
        .map(Result::unwrap)
    {
        let mut state = store
            .get_state(&state_root, Some(slot), CACHE_STATE_IN_TESTS)
            .unwrap()
            .unwrap();
        assert_eq!(state.slot(), slot);
        assert_eq!(state.canonical_root().unwrap(), state_root);
    }

    // Anchor slot is still set to the slot of the checkpoint block.
    // Note: since hot tree states the anchor slot is set to the aligned ws state slot
    // https://github.com/sigp/lighthouse/pull/6750
    let wss_aligned_slot = if checkpoint_slot % E::slots_per_epoch() == 0 {
        checkpoint_slot
    } else {
        (checkpoint_slot.epoch(E::slots_per_epoch()) + Epoch::new(1))
            .start_slot(E::slots_per_epoch())
    };
    assert_eq!(store.get_anchor_info().anchor_slot, wss_aligned_slot);
    assert_eq!(
        store.get_anchor_info().state_upper_limit,
        if checkpoint_slot == 0 {
            Slot::new(0)
        } else {
            Slot::new(u64::MAX)
        }
    );
    info!(anchor = ?store.get_anchor_info(), "anchor pre");

    // Reconstruct states.
    store.clone().reconstruct_historic_states(None).unwrap();
    assert_eq!(store.get_anchor_info().anchor_slot, wss_aligned_slot);
    assert_eq!(store.get_anchor_info().state_upper_limit, Slot::new(0));
}

// This test prunes data columns from epoch 0 and then tries to re-import them via
// the same code paths that custody backfill sync imports data columns
#[tokio::test]
async fn test_import_historical_data_columns_batch() {
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), spec);
    let start_slot = Epoch::new(0).start_slot(E::slots_per_epoch()) + 1;
    let end_slot = Epoch::new(0).end_slot(E::slots_per_epoch());
    let cgc = 128;

    let harness = get_harness_import_all_data_columns(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            (E::slots_per_epoch() * 2) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    harness.advance_slot();

    let block_root_iter = harness
        .chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .unwrap();

    let mut data_columns_list = vec![];

    // Get all data columns for epoch 0
    for block in block_root_iter {
        let (block_root, _) = block.unwrap();
        let data_columns = harness.chain.store.get_data_columns(&block_root).unwrap();
        assert!(data_columns.is_some());
        for data_column in data_columns.unwrap() {
            data_columns_list.push(data_column);
        }
    }

    harness
        .extend_chain(
            (E::slots_per_epoch() * 4) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    harness.advance_slot();

    // Prune data columns
    harness
        .chain
        .store
        .try_prune_blobs(true, Epoch::new(2))
        .unwrap();

    let block_root_iter = harness
        .chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .unwrap();

    // Assert that data columns no longer exist for epoch 0
    for block in block_root_iter {
        let (block_root, _) = block.unwrap();
        let data_columns = harness.chain.store.get_data_columns(&block_root).unwrap();
        assert!(data_columns.is_none())
    }

    // Re-import deleted data columns
    harness
        .chain
        .import_historical_data_column_batch(Epoch::new(0), data_columns_list, cgc)
        .unwrap();

    let block_root_iter = harness
        .chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .unwrap();

    // Assert that data columns now exist for epoch 0
    for block in block_root_iter {
        let (block_root, _) = block.unwrap();
        let data_columns = harness.chain.store.get_data_columns(&block_root).unwrap();
        assert!(data_columns.is_some())
    }
}

// This should verify that a data column sidecar containing mismatched block roots should fail to be imported.
// This also covers any test cases related to data columns with incorrect/invalid/mismatched block roots.
#[tokio::test]
async fn test_import_historical_data_columns_batch_mismatched_block_root() {
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), spec);
    let start_slot = Slot::new(1);
    let end_slot = Slot::new(E::slots_per_epoch() * 2 - 1);
    let cgc = 128;

    let harness = get_harness_import_all_data_columns(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            (E::slots_per_epoch() * 2) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    harness.advance_slot();

    let block_root_iter = harness
        .chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .unwrap();

    let mut data_columns_list = vec![];

    // Get all data columns from start_slot to end_slot
    // and mutate the data columns with an invalid block root
    for block in block_root_iter {
        let (block_root, _) = block.unwrap();
        let data_columns = harness.chain.store.get_data_columns(&block_root).unwrap();
        assert!(data_columns.is_some());

        for data_column in data_columns.unwrap() {
            let mut data_column = (*data_column).clone();
            if data_column.index % 2 == 0 {
                data_column.signed_block_header.message.body_root = Hash256::ZERO;
            }

            data_columns_list.push(Arc::new(data_column));
        }
    }

    harness
        .extend_chain(
            (E::slots_per_epoch() * 4) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    harness.advance_slot();

    // Prune blobs
    harness
        .chain
        .store
        .try_prune_blobs(true, Epoch::new(2))
        .unwrap();

    let block_root_iter = harness
        .chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .unwrap();

    // Assert there are no columns between start_slot and end_slot
    for block in block_root_iter {
        let (block_root, _) = block.unwrap();
        let data_columns = harness.chain.store.get_data_columns(&block_root).unwrap();
        assert!(data_columns.is_none())
    }

    // Attempt to import data columns with invalid block roots and expect a failure
    let error = harness
        .chain
        .import_historical_data_column_batch(
            start_slot.epoch(E::slots_per_epoch()),
            data_columns_list,
            cgc,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        HistoricalDataColumnError::NoBlockFound { .. }
    ));
}

/// Test that blocks and attestations that refer to states around an unaligned split state are
/// processed correctly.
#[tokio::test]
async fn process_blocks_and_attestations_for_unaligned_checkpoint() {
    let temp = tempdir().unwrap();
    let store = get_store(&temp);
    let chain_config = ChainConfig {
        reconstruct_historic_states: false,
        ..ChainConfig::default()
    };
    let harness = get_harness_generic(
        store.clone(),
        LOW_VALIDATOR_COUNT,
        chain_config,
        NodeCustodyType::Fullnode,
    );

    let all_validators = (0..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();

    let split_slot = Slot::new(E::slots_per_epoch() * 4);
    let pre_skips = 1;
    let post_skips = 1;

    // Build the chain up to the intended split slot, with 3 skips before the split.
    let slots = (1..=split_slot.as_u64() - pre_skips)
        .map(Slot::new)
        .collect::<Vec<_>>();

    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    harness
        .add_attested_blocks_at_slots(
            genesis_state.clone(),
            genesis_state_root,
            &slots,
            &all_validators,
        )
        .await;

    // Before the split slot becomes finalized, create two forking blocks that build on the split
    // block:
    //
    // - one that is invalid because it conflicts with finalization (slot <= finalized_slot)
    // - one that is valid because its slot is not finalized (slot > finalized_slot)
    let (unadvanced_split_state, unadvanced_split_state_root) =
        harness.get_current_state_and_root();

    let ((invalid_fork_block, _), _) = harness
        .make_block(unadvanced_split_state.clone(), split_slot)
        .await;
    let ((valid_fork_block, _), _) = harness
        .make_block(unadvanced_split_state.clone(), split_slot + 1)
        .await;

    // Advance the chain so that the intended split slot is finalized.
    // Do not attest in the epoch boundary slot, to make attestation production later easier (no
    // equivocations).
    let finalizing_slot = split_slot + 2 * E::slots_per_epoch();
    for _ in 0..pre_skips + post_skips {
        harness.advance_slot();
    }
    harness.extend_to_slot(finalizing_slot - 1).await;
    Box::pin(harness.add_block_at_slot(finalizing_slot, harness.get_current_state()))
        .await
        .unwrap();

    // Check that the split slot is as intended.
    let split = store.get_split_info();
    assert_eq!(split.slot, split_slot);
    assert_eq!(split.block_root, valid_fork_block.parent_root());
    assert_ne!(split.state_root, unadvanced_split_state_root);

    let invalid_fork_rpc_block = RpcBlock::new_without_blobs(None, invalid_fork_block.clone());
    // Applying the invalid block should fail.
    let err = harness
        .chain
        .process_block(
            invalid_fork_rpc_block.block_root(),
            invalid_fork_rpc_block,
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BlockError::WouldRevertFinalizedSlot { .. }));

    // Applying the valid block should succeed, but it should not become head.
    let valid_fork_rpc_block = RpcBlock::new_without_blobs(None, valid_fork_block.clone());
    harness
        .chain
        .process_block(
            valid_fork_rpc_block.block_root(),
            valid_fork_rpc_block,
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        )
        .await
        .unwrap();
    harness.chain.recompute_head_at_current_slot().await;
    assert_ne!(harness.head_block_root(), valid_fork_block.canonical_root());

    // Attestations to the split block in the next 2 epochs should be processed successfully.
    let attestation_start_slot = harness.get_current_slot();
    let attestation_end_slot = attestation_start_slot + 2 * E::slots_per_epoch();
    let (split_state_root, mut advanced_split_state) = harness
        .chain
        .store
        .get_advanced_hot_state(split.block_root, split.slot, split.state_root)
        .unwrap()
        .unwrap();
    complete_state_advance(
        &mut advanced_split_state,
        Some(split_state_root),
        attestation_start_slot,
        &harness.chain.spec,
    )
    .unwrap();
    advanced_split_state
        .build_caches(&harness.chain.spec)
        .unwrap();
    let advanced_split_state_root = advanced_split_state.update_tree_hash_cache().unwrap();
    for slot in (attestation_start_slot.as_u64()..attestation_end_slot.as_u64()).map(Slot::new) {
        let attestations = harness.make_attestations(
            &all_validators,
            &advanced_split_state,
            advanced_split_state_root,
            split.block_root.into(),
            slot,
        );
        harness.advance_slot();
        harness.process_attestations(attestations, &advanced_split_state);
    }
}

#[tokio::test]
async fn finalizes_after_resuming_from_db() {
    let validator_count = 16;
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 8;
    let first_half = num_blocks_produced / 2;

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store.clone())
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
        .extend_chain(
            first_half as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    assert!(
        harness
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint()
            .epoch
            > 0,
        "the chain should have already finalized"
    );

    let latest_slot = harness.chain.slot().expect("should have a slot");

    harness
        .chain
        .persist_fork_choice()
        .expect("should persist fork choice");
    harness
        .chain
        .persist_op_pool()
        .expect("should persist the op pool");

    let original_chain = harness.chain;

    let resumed_harness = BeaconChainHarness::<DiskHarnessType<E>>::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .resumed_disk_store(store)
        .testing_slot_clock(original_chain.slot_clock.clone())
        .execution_layer(original_chain.execution_layer.clone())
        .build();

    assert_chains_pretty_much_the_same(&original_chain, &resumed_harness.chain);

    // Set the slot clock of the resumed harness to be in the slot following the previous harness.
    //
    // This allows us to produce the block at the next slot.
    resumed_harness
        .chain
        .slot_clock
        .set_slot(latest_slot.as_u64() + 1);

    resumed_harness
        .extend_chain(
            (num_blocks_produced - first_half) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let state = &resumed_harness.chain.head_snapshot().beacon_state;
    assert_eq!(
        state.slot(),
        num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );
}

#[allow(clippy::large_stack_frames)]
#[tokio::test]
async fn revert_minority_fork_on_resume() {
    let validator_count = 16;
    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

    let fork_epoch = Epoch::new(4);
    let fork_slot = fork_epoch.start_slot(slots_per_epoch);
    let initial_blocks = slots_per_epoch * fork_epoch.as_u64() - 1;
    let post_fork_blocks = slots_per_epoch * 3;

    let mut spec1 = MinimalEthSpec::default_spec();
    spec1.altair_fork_epoch = None;
    let mut spec2 = MinimalEthSpec::default_spec();
    spec2.altair_fork_epoch = Some(fork_epoch);

    let seconds_per_slot = spec1.seconds_per_slot;

    let all_validators = (0..validator_count).collect::<Vec<usize>>();

    // Chain with no fork epoch configured.
    let db_path1 = tempdir().unwrap();
    let store1 = get_store_generic(&db_path1, StoreConfig::default(), spec1.clone());
    let harness1 = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec1.clone().into())
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store1)
        .mock_execution_layer()
        .build();

    // Chain with fork epoch configured.
    let db_path2 = tempdir().unwrap();
    let store2 = get_store_generic(&db_path2, StoreConfig::default(), spec2.clone());
    let harness2 = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec2.clone().into())
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store2)
        .mock_execution_layer()
        .build();

    // Apply the same blocks to both chains initially.
    let mut state = harness1.get_current_state();
    let mut block_root = harness1.chain.genesis_block_root;
    for slot in (1..=initial_blocks).map(Slot::new) {
        let state_root = state.update_tree_hash_cache().unwrap();

        let attestations = harness1.make_attestations(
            &all_validators,
            &state,
            state_root,
            block_root.into(),
            slot,
        );
        harness1.set_current_slot(slot);
        harness2.set_current_slot(slot);
        harness1.process_attestations(attestations.clone(), &state);
        harness2.process_attestations(attestations, &state);

        let ((block, blobs), new_state) = harness1.make_block(state, slot).await;

        harness1
            .process_block(slot, block.canonical_root(), (block.clone(), blobs.clone()))
            .await
            .unwrap();
        harness2
            .process_block(slot, block.canonical_root(), (block.clone(), blobs.clone()))
            .await
            .unwrap();

        state = new_state;
        block_root = block.canonical_root();
    }

    assert_eq!(harness1.head_slot(), fork_slot - 1);
    assert_eq!(harness2.head_slot(), fork_slot - 1);

    // Fork the two chains.
    let mut state1 = state.clone();
    let mut state2 = state.clone();

    let mut majority_blocks = vec![];

    for i in 0..post_fork_blocks {
        let slot = fork_slot + i;

        // Attestations on majority chain.
        let state_root = state.update_tree_hash_cache().unwrap();

        let attestations = harness2.make_attestations(
            &all_validators,
            &state2,
            state_root,
            block_root.into(),
            slot,
        );
        harness2.set_current_slot(slot);
        harness2.process_attestations(attestations, &state2);

        // Minority chain block (no attesters).
        let ((block1, blobs1), new_state1) = harness1.make_block(state1, slot).await;
        harness1
            .process_block(slot, block1.canonical_root(), (block1, blobs1))
            .await
            .unwrap();
        state1 = new_state1;

        // Majority chain block (all attesters).
        let ((block2, blobs2), new_state2) = harness2.make_block(state2, slot).await;
        harness2
            .process_block(slot, block2.canonical_root(), (block2.clone(), blobs2))
            .await
            .unwrap();

        state2 = new_state2;
        block_root = block2.canonical_root();

        majority_blocks.push(block2);
    }

    let end_slot = fork_slot + post_fork_blocks - 1;
    assert_eq!(harness1.head_slot(), end_slot);
    assert_eq!(harness2.head_slot(), end_slot);

    // Resume from disk with the hard-fork activated: this should revert the post-fork blocks.
    // We have to do some hackery with the `slot_clock` so that the correct slot is set when
    // the beacon chain builder loads the head block.
    drop(harness1);
    let resume_store = get_store_generic(&db_path1, StoreConfig::default(), spec2.clone());

    let resumed_harness = TestHarness::builder(MinimalEthSpec)
        .spec(spec2.clone().into())
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .resumed_disk_store(resume_store)
        .override_store_mutator(Box::new(move |mut builder| {
            builder = builder
                .resume_from_db()
                .unwrap()
                .testing_slot_clock(Duration::from_secs(seconds_per_slot))
                .unwrap();
            builder
                .get_slot_clock()
                .unwrap()
                .set_slot(end_slot.as_u64());
            builder
        }))
        .mock_execution_layer()
        .build();

    // Head should now be just before the fork.
    resumed_harness.chain.recompute_head_at_current_slot().await;
    assert_eq!(resumed_harness.head_slot(), fork_slot - 1);

    // Fork choice should only know the canonical head. When we reverted the head we also should
    // have called `reset_fork_choice_to_finalization` which rebuilds fork choice from scratch
    // without the reverted block.
    assert_eq!(
        resumed_harness.chain.heads(),
        vec![(resumed_harness.head_block_root(), fork_slot - 1)]
    );

    // Apply blocks from the majority chain and trigger finalization.
    let initial_split_slot = resumed_harness.chain.store.get_split_slot();
    for block in &majority_blocks {
        resumed_harness
            .process_block_result((block.clone(), None))
            .await
            .unwrap();

        // The canonical head should be the block from the majority chain.
        resumed_harness.chain.recompute_head_at_current_slot().await;
        assert_eq!(resumed_harness.head_slot(), block.slot());
        assert_eq!(resumed_harness.head_block_root(), block.canonical_root());
    }
    let advanced_split_slot = resumed_harness.chain.store.get_split_slot();

    // Check that the migration ran successfully.
    assert!(advanced_split_slot > initial_split_slot);

    // Check that there is only a single head now matching harness2 (the minority chain is gone).
    let heads = resumed_harness.chain.heads();
    assert_eq!(heads, harness2.chain.heads());
    assert_eq!(heads.len(), 1);
}

// This test checks whether the schema downgrade from the latest version to some minimum supported
// version is correct. This is the easiest schema test to write without historic versions of
// Lighthouse on-hand, but has the disadvantage that the min version needs to be adjusted manually
// as old downgrades are deprecated.
async fn schema_downgrade_to_min_version(
    store_config: StoreConfig,
    reconstruct_historic_states: bool,
) {
    let num_blocks_produced = E::slots_per_epoch() * 4;
    let db_path = tempdir().unwrap();
    let spec = test_spec::<E>();

    let chain_config = ChainConfig {
        reconstruct_historic_states,
        ..ChainConfig::default()
    };

    let store = get_store_generic(&db_path, store_config.clone(), spec.clone());
    let harness = get_harness_generic(
        store.clone(),
        LOW_VALIDATOR_COUNT,
        chain_config.clone(),
        NodeCustodyType::Fullnode,
    );

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let min_version = if spec.is_fulu_scheduled() {
        SchemaVersion(27)
    } else {
        SchemaVersion(22)
    };

    // Save the slot clock so that the new harness doesn't revert in time.
    let slot_clock = harness.chain.slot_clock.clone();

    // Close the database to ensure everything is written to disk.
    drop(store);
    drop(harness);

    // Re-open the store.
    let store = get_store_generic(&db_path, store_config, spec);

    // Downgrade.
    migrate_schema::<DiskHarnessType<E>>(store.clone(), CURRENT_SCHEMA_VERSION, min_version)
        .expect("schema downgrade to minimum version should work");

    // Upgrade back.
    migrate_schema::<DiskHarnessType<E>>(store.clone(), min_version, CURRENT_SCHEMA_VERSION)
        .expect("schema upgrade from minimum version should work");

    // Recreate the harness.
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .chain_config(chain_config)
        .keypairs(KEYPAIRS[0..LOW_VALIDATOR_COUNT].to_vec())
        .testing_slot_clock(slot_clock)
        .resumed_disk_store(store.clone())
        .mock_execution_layer()
        .build();

    // Check chain dump for appropriate range depending on whether this is an archive node.
    let chain_dump_start_slot = if reconstruct_historic_states {
        Slot::new(0)
    } else {
        store.get_split_slot()
    };

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store.clone());
    check_chain_dump_from_slot(
        &harness,
        chain_dump_start_slot,
        num_blocks_produced + 1 - chain_dump_start_slot.as_u64(),
    );
    check_iterators_from_slot(&harness, chain_dump_start_slot);

    // Check that downgrading beyond the minimum version fails (bound is *tight*).
    let min_version_sub_1 = SchemaVersion(min_version.as_u64().checked_sub(1).unwrap());
    migrate_schema::<DiskHarnessType<E>>(store.clone(), CURRENT_SCHEMA_VERSION, min_version_sub_1)
        .expect_err("should not downgrade below minimum version");
}

// Schema upgrade/downgrade on an archive node where the optimised migration does apply due
// to the split state being aligned to a diff layer.
#[tokio::test]
async fn schema_downgrade_to_min_version_archive_node_grid_aligned() {
    // Need to use 3 as the hierarchy exponent to get diffs on every epoch boundary with minimal
    // spec.
    schema_downgrade_to_min_version(
        StoreConfig {
            hierarchy_config: HierarchyConfig::from_str("3,4,5").unwrap(),
            prune_payloads: false,
            ..StoreConfig::default()
        },
        true,
    )
    .await
}

// Schema upgrade/downgrade on an archive node where the optimised migration DOES NOT apply
// due to the split state NOT being aligned to a diff layer.
#[tokio::test]
async fn schema_downgrade_to_min_version_archive_node_grid_unaligned() {
    schema_downgrade_to_min_version(
        StoreConfig {
            hierarchy_config: HierarchyConfig::from_str("7").unwrap(),
            prune_payloads: false,
            ..StoreConfig::default()
        },
        true,
    )
    .await
}

// Schema upgrade/downgrade on a full node with a fairly normal per-epoch diff config.
#[tokio::test]
async fn schema_downgrade_to_min_version_full_node_per_epoch_diffs() {
    schema_downgrade_to_min_version(
        StoreConfig {
            hierarchy_config: HierarchyConfig::from_str("3,4,5").unwrap(),
            prune_payloads: false,
            ..StoreConfig::default()
        },
        false,
    )
    .await
}

// Schema upgrade/downgrade on a full node with dense per-slot diffs.
#[tokio::test]
async fn schema_downgrade_to_min_version_full_node_dense_diffs() {
    schema_downgrade_to_min_version(
        StoreConfig {
            hierarchy_config: HierarchyConfig::from_str("0,3,4,5").unwrap(),
            prune_payloads: false,
            ..StoreConfig::default()
        },
        true,
    )
    .await
}

/// Check that blob pruning prunes blobs older than the data availability boundary.
#[tokio::test]
async fn deneb_prune_blobs_happy_case() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    if store.get_chain_spec().is_peer_das_scheduled() {
        // Blob pruning no longer needed since Fulu / PeerDAS
        return;
    }

    let Some(deneb_fork_epoch) = store.get_chain_spec().deneb_fork_epoch else {
        // No-op prior to Deneb.
        return;
    };
    let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

    let num_blocks_produced = E::slots_per_epoch() * 8;
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Prior to manual pruning with an artifically low data availability boundary all blobs should
    // be stored.
    assert_eq!(
        store.get_blob_info().oldest_blob_slot,
        Some(deneb_fork_slot)
    );
    check_blob_existence(&harness, Slot::new(1), harness.head_slot(), true);

    // Trigger blob pruning of blobs older than epoch 2.
    let data_availability_boundary = Epoch::new(2);
    store
        .try_prune_blobs(true, data_availability_boundary)
        .unwrap();

    // Check oldest blob slot is updated accordingly and prior blobs have been deleted.
    let oldest_blob_slot = store.get_blob_info().oldest_blob_slot.unwrap();
    assert_eq!(
        oldest_blob_slot,
        data_availability_boundary.start_slot(E::slots_per_epoch())
    );
    check_blob_existence(&harness, Slot::new(0), oldest_blob_slot - 1, false);
    check_blob_existence(&harness, oldest_blob_slot, harness.head_slot(), true);
}

/// Check that blob pruning does not prune without finalization.
#[tokio::test]
async fn deneb_prune_blobs_no_finalization() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    if store.get_chain_spec().is_peer_das_scheduled() {
        // Blob pruning no longer needed since Fulu / PeerDAS
        return;
    }

    let Some(deneb_fork_epoch) = store.get_chain_spec().deneb_fork_epoch else {
        // No-op prior to Deneb.
        return;
    };
    let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

    let initial_num_blocks = E::slots_per_epoch() * 5;
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Finalize to epoch 3.
    harness
        .extend_chain(
            initial_num_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Extend the chain for another few epochs without attestations.
    let unfinalized_num_blocks = E::slots_per_epoch() * 3;
    harness.advance_slot();
    harness
        .extend_chain(
            unfinalized_num_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    // Finalization should be at epoch 3.
    let finalized_slot = Slot::new(E::slots_per_epoch() * 3);
    assert_eq!(harness.get_current_state().finalized_checkpoint().epoch, 3);
    assert_eq!(store.get_split_slot(), finalized_slot);

    // All blobs should still be available.
    assert_eq!(
        store.get_blob_info().oldest_blob_slot,
        Some(deneb_fork_slot)
    );
    check_blob_existence(&harness, Slot::new(0), harness.head_slot(), true);

    // Attempt blob pruning of blobs older than epoch 4, which is newer than finalization.
    let data_availability_boundary = Epoch::new(4);
    store
        .try_prune_blobs(true, data_availability_boundary)
        .unwrap();

    // Check oldest blob slot is only updated to finalization, and NOT to the DAB.
    let oldest_blob_slot = store.get_blob_info().oldest_blob_slot.unwrap();
    assert_eq!(oldest_blob_slot, finalized_slot);
    check_blob_existence(&harness, Slot::new(0), finalized_slot - 1, false);
    check_blob_existence(&harness, finalized_slot, harness.head_slot(), true);
}

/// Check that blob pruning does not fail trying to prune across the fork boundary.
#[tokio::test]
async fn prune_blobs_across_fork_boundary() {
    let mut spec = ForkName::Capella.make_genesis_spec(E::default_spec());

    let deneb_fork_epoch = Epoch::new(4);
    spec.deneb_fork_epoch = Some(deneb_fork_epoch);
    let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

    let electra_fork_epoch = Epoch::new(8);
    spec.electra_fork_epoch = Some(electra_fork_epoch);

    let fulu_fork_epoch = Epoch::new(12);
    spec.fulu_fork_epoch = Some(fulu_fork_epoch);

    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), spec);

    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let blocks_to_deneb_finalization = E::slots_per_epoch() * 7;
    let blocks_to_electra_finalization = E::slots_per_epoch() * 4;
    let blocks_to_fulu_finalization = E::slots_per_epoch() * 4;

    // Extend the chain to epoch 7
    // Finalize to epoch 5 (Deneb).
    harness
        .extend_chain(
            blocks_to_deneb_finalization as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Finalization should be at epoch 5 (Deneb).
    let finalized_epoch = Epoch::new(5);
    let finalized_slot = finalized_epoch.start_slot(E::slots_per_epoch());
    assert_eq!(
        harness.get_current_state().finalized_checkpoint().epoch,
        finalized_epoch
    );
    assert_eq!(store.get_split_slot(), finalized_slot);

    // All blobs should still be available.
    assert_eq!(
        store.get_blob_info().oldest_blob_slot,
        Some(deneb_fork_slot)
    );
    check_blob_existence(&harness, Slot::new(0), harness.head_slot(), true);

    // Attempt pruning with data availability epochs that precede the fork epoch.
    // No pruning should occur.
    assert!(deneb_fork_epoch < finalized_epoch);
    for data_availability_boundary in [Epoch::new(0), Epoch::new(3), deneb_fork_epoch] {
        store
            .try_prune_blobs(true, data_availability_boundary)
            .unwrap();

        // Check oldest blob slot is not updated.
        assert_eq!(
            store.get_blob_info().oldest_blob_slot,
            Some(deneb_fork_slot)
        );
    }
    // All blobs should still be available.
    check_blob_existence(&harness, Slot::new(0), harness.head_slot(), true);

    // Prune one epoch past the fork.
    let pruned_slot = (deneb_fork_epoch + 1).start_slot(E::slots_per_epoch());
    store.try_prune_blobs(true, deneb_fork_epoch + 1).unwrap();
    assert_eq!(store.get_blob_info().oldest_blob_slot, Some(pruned_slot));
    check_blob_existence(&harness, Slot::new(0), pruned_slot - 1, false);
    check_blob_existence(&harness, pruned_slot, harness.head_slot(), true);

    // Extend the chain to epoch 11
    // Finalize to epoch 9 (Electra)
    harness.advance_slot();
    harness
        .extend_chain(
            blocks_to_electra_finalization as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Finalization should be at epoch 9 (Electra).
    let finalized_epoch = Epoch::new(9);
    let finalized_slot = finalized_epoch.start_slot(E::slots_per_epoch());
    assert_eq!(
        harness.get_current_state().finalized_checkpoint().epoch,
        finalized_epoch
    );
    assert_eq!(store.get_split_slot(), finalized_slot);

    // All blobs since last pruning during Deneb should still be available.
    assert_eq!(store.get_blob_info().oldest_blob_slot, Some(pruned_slot));

    let electra_first_slot = electra_fork_epoch.start_slot(E::slots_per_epoch());
    // Check that blobs exist from the pruned slot to electra
    check_blob_existence(&harness, pruned_slot, electra_first_slot - 1, true);

    // Trigger pruning on Electra
    let pruned_slot = (electra_fork_epoch + 1).start_slot(E::slots_per_epoch());

    store.try_prune_blobs(true, finalized_epoch).unwrap();
    assert_eq!(store.get_blob_info().oldest_blob_slot, Some(finalized_slot));
    check_blob_existence(&harness, Slot::new(0), pruned_slot - 1, false);
    check_blob_existence(&harness, pruned_slot, harness.head_slot(), true);

    // Check that blobs have been pruned up to the pruned slot
    check_blob_existence(&harness, Slot::new(0), pruned_slot - 1, false);
    // Check that blobs exist from electra to the current head
    check_blob_existence(&harness, electra_first_slot, harness.head_slot(), true);

    // Extend the chain to epoch 15
    // Finalize to epoch 13 (Fulu)
    harness.advance_slot();
    harness
        .extend_chain(
            blocks_to_fulu_finalization as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Finalization should be at epoch 13 (Fulu).
    let finalized_epoch = Epoch::new(13);
    let finalized_slot = finalized_epoch.start_slot(E::slots_per_epoch());
    assert_eq!(
        harness.get_current_state().finalized_checkpoint().epoch,
        finalized_epoch
    );
    assert_eq!(store.get_split_slot(), finalized_slot);

    // All blobs since last pruning during Electra should still be available.
    assert_eq!(store.get_blob_info().oldest_blob_slot, Some(pruned_slot));

    let fulu_first_slot = fulu_fork_epoch.start_slot(E::slots_per_epoch());
    // Check that blobs have been pruned up to the pruned slot
    check_blob_existence(&harness, Slot::new(0), pruned_slot - 1, false);
    // Check that blobs exist from the pruned slot to Fulu
    check_blob_existence(&harness, pruned_slot, fulu_first_slot - 1, true);
    // Check that blobs do not exist from Fulu to the current head
    check_blob_existence(&harness, fulu_first_slot, harness.head_slot(), false);

    // Attempt pruning with at different epochs. No pruning should occur for epochs
    // preceding Fulu, as we have already triggered pruning pre-Fulu. Pruning should occur
    // for epochs after Fulu.
    assert!(fulu_fork_epoch < finalized_epoch);
    for data_availability_boundary in [
        Epoch::new(7),
        electra_fork_epoch,
        Epoch::new(9),
        Epoch::new(11),
        fulu_fork_epoch,
        Epoch::new(15),
    ] {
        store
            .try_prune_blobs(true, data_availability_boundary)
            .unwrap();

        let oldest_slot = data_availability_boundary.start_slot(E::slots_per_epoch());

        if data_availability_boundary < fulu_fork_epoch {
            // Pre Fulu fork epochs
            // Check oldest blob slot is not updated.
            assert!(store.get_blob_info().oldest_blob_slot >= Some(oldest_slot));
            check_blob_existence(&harness, Slot::new(0), oldest_slot - 1, false);
            // Blobs should exist
            check_blob_existence(&harness, oldest_slot, harness.head_slot(), true);
        } else {
            // Fulu fork epochs
            // Pruning should have been triggered
            assert!(store.get_blob_info().oldest_blob_slot <= Some(oldest_slot));
            // Oldest blost slot should never be greater than the first fulu slot
            let fulu_first_slot = fulu_fork_epoch.start_slot(E::slots_per_epoch());
            assert!(store.get_blob_info().oldest_blob_slot <= Some(fulu_first_slot));
            // Blobs should not exist post-Fulu
            check_blob_existence(&harness, oldest_slot, harness.head_slot(), false);
            // Data columns should exist post-Fulu
            check_data_column_existence(&harness, oldest_slot, harness.head_slot(), true);
        };
    }
}

/// Check that blob pruning prunes blobs older than the data availability boundary with margin
/// applied.
#[tokio::test]
async fn deneb_prune_blobs_margin1() {
    deneb_prune_blobs_margin_test(1).await;
}

#[tokio::test]
async fn deneb_prune_blobs_margin3() {
    deneb_prune_blobs_margin_test(3).await;
}

#[tokio::test]
async fn deneb_prune_blobs_margin4() {
    deneb_prune_blobs_margin_test(4).await;
}

async fn deneb_prune_blobs_margin_test(margin: u64) {
    let config = StoreConfig {
        blob_prune_margin_epochs: margin,
        ..StoreConfig::default()
    };
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, config, test_spec::<E>());

    if store.get_chain_spec().is_peer_das_scheduled() {
        // Blob pruning no longer needed since Fulu / PeerDAS
        return;
    }

    let Some(deneb_fork_epoch) = store.get_chain_spec().deneb_fork_epoch else {
        // No-op prior to Deneb.
        return;
    };
    let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

    let num_blocks_produced = E::slots_per_epoch() * 8;
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Prior to manual pruning with an artifically low data availability boundary all blobs should
    // be stored.
    assert_eq!(
        store.get_blob_info().oldest_blob_slot,
        Some(deneb_fork_slot)
    );
    check_blob_existence(&harness, Slot::new(1), harness.head_slot(), true);

    // Trigger blob pruning of blobs older than epoch 6 - margin (6 is the minimum, due to
    // finalization).
    let data_availability_boundary = Epoch::new(6);
    let effective_data_availability_boundary =
        data_availability_boundary - store.get_config().blob_prune_margin_epochs;
    assert!(
        effective_data_availability_boundary > 0,
        "must be > 0 because epoch 0 won't get pruned alone"
    );
    store
        .try_prune_blobs(true, data_availability_boundary)
        .unwrap();

    // Check oldest blob slot is updated accordingly and prior blobs have been deleted.
    let oldest_blob_slot = store.get_blob_info().oldest_blob_slot.unwrap();
    assert_eq!(
        oldest_blob_slot,
        effective_data_availability_boundary.start_slot(E::slots_per_epoch())
    );
    check_blob_existence(&harness, Slot::new(0), oldest_blob_slot - 1, false);
    check_blob_existence(&harness, oldest_blob_slot, harness.head_slot(), true);
}

/// Check that a database with `blobs_db=false` can be upgraded to `blobs_db=true` before Deneb.
#[tokio::test]
async fn change_to_separate_blobs_db_before_deneb() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    // Only run this test on forks prior to Deneb. If the blobs database already has blobs, we can't
    // move it.
    if store.get_chain_spec().deneb_fork_epoch.is_some() {
        return;
    }

    let init_blob_info = store.get_blob_info();
    assert!(
        init_blob_info.blobs_db,
        "separate blobs DB should be the default"
    );

    // Change to `blobs_db=false` to emulate legacy Deneb DB.
    let legacy_blob_info = BlobInfo {
        blobs_db: false,
        ..init_blob_info
    };
    store
        .compare_and_set_blob_info_with_write(init_blob_info.clone(), legacy_blob_info.clone())
        .unwrap();
    assert_eq!(store.get_blob_info(), legacy_blob_info);

    // Re-open the DB and check that `blobs_db` gets changed back to true.
    drop(store);
    let store = get_store(&db_path);
    assert_eq!(store.get_blob_info(), init_blob_info);
}

/// Check that there are blob sidecars (or not) at every slot in the range.
fn check_blob_existence(
    harness: &TestHarness,
    start_slot: Slot,
    end_slot: Slot,
    should_exist: bool,
) {
    let mut blobs_seen = 0;
    for (block_root, slot) in harness
        .chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .unwrap()
        .map(Result::unwrap)
    {
        if let Some(blobs) = harness.chain.store.get_blobs(&block_root).unwrap().blobs() {
            assert!(should_exist, "blobs at slot {slot} exist but should not");
            blobs_seen += blobs.len();
        } else {
            // We don't actually store empty blobs, so unfortunately we can't assert anything
            // meaningful here (like asserting that the blob should not exist).
        }
    }
    if should_exist {
        assert_ne!(blobs_seen, 0, "expected non-zero number of blobs");
    }
}

/// Check that blob pruning prunes data columns older than the data availability boundary.
#[tokio::test]
async fn fulu_prune_data_columns_happy_case() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    if !store.get_chain_spec().is_peer_das_scheduled() {
        // No-op if PeerDAS not scheduled.
        return;
    }
    let Some(fulu_fork_epoch) = store.get_chain_spec().fulu_fork_epoch else {
        // No-op prior to Fulu.
        return;
    };
    let fulu_fork_slot = fulu_fork_epoch.start_slot(E::slots_per_epoch());

    let num_blocks_produced = E::slots_per_epoch() * 8;
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Prior to manual pruning with an artifically low data availability boundary all data columns
    // should be stored.
    assert_eq!(
        store.get_data_column_info().oldest_data_column_slot,
        Some(fulu_fork_slot)
    );
    check_data_column_existence(&harness, Slot::new(1), harness.head_slot(), true);

    // Trigger pruning of data columns older than epoch 2.
    let data_availability_boundary = Epoch::new(2);
    store
        .try_prune_blobs(true, data_availability_boundary)
        .unwrap();

    // Check oldest data column slot is updated accordingly and prior data columns have been
    // deleted.
    let oldest_data_column_slot = store
        .get_data_column_info()
        .oldest_data_column_slot
        .unwrap();
    assert_eq!(
        oldest_data_column_slot,
        data_availability_boundary.start_slot(E::slots_per_epoch())
    );
    check_data_column_existence(&harness, Slot::new(0), oldest_data_column_slot - 1, false);
    check_data_column_existence(&harness, oldest_data_column_slot, harness.head_slot(), true);
}

/// Check that blob pruning does not prune data columns without finalization.
#[tokio::test]
async fn fulu_prune_data_columns_no_finalization() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    if !store.get_chain_spec().is_peer_das_scheduled() {
        // No-op if PeerDAS not scheduled.
        return;
    }
    let Some(fulu_fork_epoch) = store.get_chain_spec().fulu_fork_epoch else {
        // No-op prior to Fulu.
        return;
    };
    let fulu_fork_slot = fulu_fork_epoch.start_slot(E::slots_per_epoch());

    let initial_num_blocks = E::slots_per_epoch() * 5;
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Finalize to epoch 3.
    harness
        .extend_chain(
            initial_num_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Extend the chain for another few epochs without attestations.
    let unfinalized_num_blocks = E::slots_per_epoch() * 3;
    harness.advance_slot();
    harness
        .extend_chain(
            unfinalized_num_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    // Finalization should be at epoch 3.
    let finalized_slot = Slot::new(E::slots_per_epoch() * 3);
    assert_eq!(harness.get_current_state().finalized_checkpoint().epoch, 3);
    assert_eq!(store.get_split_slot(), finalized_slot);

    // All data columns should still be available.
    assert_eq!(
        store.get_data_column_info().oldest_data_column_slot,
        Some(fulu_fork_slot)
    );
    check_data_column_existence(&harness, Slot::new(0), harness.head_slot(), true);

    // Attempt pruning of data columns older than epoch 4, which is newer than finalization.
    let data_availability_boundary = Epoch::new(4);
    store
        .try_prune_blobs(true, data_availability_boundary)
        .unwrap();

    // Check oldest data column slot is only updated to finalization, and NOT to the DAB.
    let oldest_data_column_slot = store
        .get_data_column_info()
        .oldest_data_column_slot
        .unwrap();
    assert_eq!(oldest_data_column_slot, finalized_slot);
    check_data_column_existence(&harness, Slot::new(0), finalized_slot - 1, false);
    check_data_column_existence(&harness, finalized_slot, harness.head_slot(), true);
}

/// Check that data column pruning does not fail trying to prune across the fork boundary.
#[tokio::test]
async fn fulu_prune_data_columns_fork_boundary() {
    let mut spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    let fulu_fork_epoch = Epoch::new(4);
    spec.fulu_fork_epoch = Some(fulu_fork_epoch);
    let fulu_fork_slot = fulu_fork_epoch.start_slot(E::slots_per_epoch());

    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), spec);

    if !store.get_chain_spec().is_peer_das_scheduled() {
        // No-op if PeerDAS not scheduled.
        panic!("PeerDAS not scheduled");
        //return;
    }

    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let num_blocks = E::slots_per_epoch() * 7;

    // Finalize to epoch 5.
    harness
        .extend_chain(
            num_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Finalization should be at epoch 5.
    let finalized_epoch = Epoch::new(5);
    let finalized_slot = finalized_epoch.start_slot(E::slots_per_epoch());
    assert_eq!(
        harness.get_current_state().finalized_checkpoint().epoch,
        finalized_epoch
    );
    assert_eq!(store.get_split_slot(), finalized_slot);

    // All data columns should still be available.
    assert_eq!(
        store.get_data_column_info().oldest_data_column_slot,
        Some(fulu_fork_slot)
    );
    check_data_column_existence(&harness, Slot::new(0), harness.head_slot(), true);

    // Attempt pruning with data availability epochs that precede the fork epoch.
    // No pruning should occur.
    assert!(fulu_fork_epoch < finalized_epoch);
    for data_availability_boundary in [Epoch::new(0), Epoch::new(3), fulu_fork_epoch] {
        store
            .try_prune_blobs(true, data_availability_boundary)
            .unwrap();

        // Check oldest data column slot is not updated.
        assert_eq!(
            store.get_data_column_info().oldest_data_column_slot,
            Some(fulu_fork_slot)
        );
    }
    // All data columns should still be available.
    check_data_column_existence(&harness, Slot::new(0), harness.head_slot(), true);

    // Prune one epoch past the fork.
    let pruned_slot = (fulu_fork_epoch + 1).start_slot(E::slots_per_epoch());
    store.try_prune_blobs(true, fulu_fork_epoch + 1).unwrap();
    assert_eq!(
        store.get_data_column_info().oldest_data_column_slot,
        Some(pruned_slot)
    );
    check_data_column_existence(&harness, Slot::new(0), pruned_slot - 1, false);
    check_data_column_existence(&harness, pruned_slot, harness.head_slot(), true);
}

#[tokio::test]
async fn test_column_da_boundary() {
    let mut spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    let fulu_fork_epoch = Epoch::new(4);
    spec.fulu_fork_epoch = Some(fulu_fork_epoch);
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), spec);

    if !store.get_chain_spec().is_peer_das_scheduled() {
        // No-op if PeerDAS not scheduled.
        panic!("PeerDAS not scheduled");
    }

    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // The column da boundary should be the fulu fork epoch
    assert_eq!(
        harness.chain.column_data_availability_boundary(),
        Some(fulu_fork_epoch)
    );
}

#[tokio::test]
async fn test_earliest_custodied_data_column_epoch() {
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, StoreConfig::default(), spec);
    let custody_info_epoch = Epoch::new(4);

    if !store.get_chain_spec().is_peer_das_scheduled() {
        // No-op if PeerDAS not scheduled.
        panic!("PeerDAS not scheduled");
    }

    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // earliest custody info is set to the last slot in `custody_info_epoch`
    harness
        .chain
        .update_data_column_custody_info(Some(custody_info_epoch.end_slot(E::slots_per_epoch())));

    // earliest custodied data column epoch should be `custody_info_epoch` + 1
    assert_eq!(
        harness.chain.earliest_custodied_data_column_epoch(),
        Some(custody_info_epoch + 1)
    );

    // earliest custody info is set to the first slot in `custody_info_epoch`
    harness
        .chain
        .update_data_column_custody_info(Some(custody_info_epoch.start_slot(E::slots_per_epoch())));

    // earliest custodied data column epoch should be `custody_info_epoch`
    assert_eq!(
        harness.chain.earliest_custodied_data_column_epoch(),
        Some(custody_info_epoch)
    );
}

/// Check that blob pruning prunes data columns older than the data availability boundary with
/// margin applied.
#[tokio::test]
async fn fulu_prune_data_columns_margin1() {
    fulu_prune_data_columns_margin_test(1).await;
}

#[tokio::test]
async fn fulu_prune_data_columns_margin3() {
    fulu_prune_data_columns_margin_test(3).await;
}

#[tokio::test]
async fn fulu_prune_data_columns_margin4() {
    fulu_prune_data_columns_margin_test(4).await;
}

async fn fulu_prune_data_columns_margin_test(margin: u64) {
    let config = StoreConfig {
        blob_prune_margin_epochs: margin,
        ..StoreConfig::default()
    };
    let db_path = tempdir().unwrap();
    let store = get_store_generic(&db_path, config, test_spec::<E>());

    if !store.get_chain_spec().is_peer_das_scheduled() {
        // No-op if PeerDAS not scheduled.
        return;
    }
    let Some(fulu_fork_epoch) = store.get_chain_spec().fulu_fork_epoch else {
        // No-op prior to Fulu.
        return;
    };
    let fulu_fork_slot = fulu_fork_epoch.start_slot(E::slots_per_epoch());

    let num_blocks_produced = E::slots_per_epoch() * 8;
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Prior to manual pruning with an artifically low data availability boundary all blobs should
    // be stored.
    assert_eq!(
        store.get_data_column_info().oldest_data_column_slot,
        Some(fulu_fork_slot)
    );
    check_data_column_existence(&harness, Slot::new(1), harness.head_slot(), true);

    // Trigger blob pruning of blobs older than epoch 6 - margin (6 is the minimum, due to
    // finalization).
    let data_availability_boundary = Epoch::new(6);
    let effective_data_availability_boundary =
        data_availability_boundary - store.get_config().blob_prune_margin_epochs;
    assert!(
        effective_data_availability_boundary > 0,
        "must be > 0 because epoch 0 won't get pruned alone"
    );
    store
        .try_prune_blobs(true, data_availability_boundary)
        .unwrap();

    // Check oldest blob slot is updated accordingly and prior blobs have been deleted.
    let oldest_data_column_slot = store
        .get_data_column_info()
        .oldest_data_column_slot
        .unwrap();
    assert_eq!(
        oldest_data_column_slot,
        effective_data_availability_boundary.start_slot(E::slots_per_epoch())
    );
    check_data_column_existence(&harness, Slot::new(0), oldest_data_column_slot - 1, false);
    check_data_column_existence(&harness, oldest_data_column_slot, harness.head_slot(), true);
}

/// Check tat there are data column sidecars (or not) at every slot in the range.
fn check_data_column_existence(
    harness: &TestHarness,
    start_slot: Slot,
    end_slot: Slot,
    should_exist: bool,
) {
    let mut columns_seen = 0;
    for (block_root, slot) in harness
        .chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .unwrap()
        .map(Result::unwrap)
    {
        if let Some(columns) = harness.chain.store.get_data_columns(&block_root).unwrap() {
            assert!(should_exist, "columns at slot {slot} exist but should not");
            columns_seen += columns.len();
        } else {
            // We don't actually store empty columns, so unfortunately we can't assert anything
            // meaningful here (like asserting that the column should not exist).
        }
    }
    if should_exist {
        assert_ne!(columns_seen, 0, "expected non-zero number of columns");
    }
}

#[tokio::test]
async fn prune_historic_states() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let genesis_state_root = harness.chain.genesis_state_root;

    let genesis_state = harness
        .chain
        .get_state(&genesis_state_root, None, CACHE_STATE_IN_TESTS)
        .unwrap()
        .unwrap();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Check historical states are present.
    let first_epoch_state_roots = harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .unwrap()
        .take(E::slots_per_epoch() as usize)
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    for &(state_root, slot) in &first_epoch_state_roots {
        assert!(
            store
                .get_state(&state_root, Some(slot), CACHE_STATE_IN_TESTS)
                .unwrap()
                .is_some()
        );
    }

    store
        .prune_historic_states(genesis_state_root, &genesis_state)
        .unwrap();

    // Check that anchor info is updated.
    let anchor_info = store.get_anchor_info();
    assert_eq!(anchor_info.state_lower_limit, 0);
    assert_eq!(anchor_info.state_upper_limit, STATE_UPPER_LIMIT_NO_RETAIN);

    // Ensure all epoch 0 states other than the genesis have been pruned.
    for &(state_root, slot) in &first_epoch_state_roots {
        assert_eq!(
            store
                .get_state(&state_root, Some(slot), CACHE_STATE_IN_TESTS)
                .unwrap()
                .is_some(),
            slot == 0
        );
    }

    // Run for another two epochs.
    let additional_blocks_produced = 2 * E::slots_per_epoch();
    harness
        .extend_slots(additional_blocks_produced as usize)
        .await;

    check_finalization(&harness, num_blocks_produced + additional_blocks_produced);
    check_split_slot(&harness, store);
}

// Test the function `get_ancestor_state_root` for slots prior to the split where we only have
// sparse summaries stored.
#[tokio::test]
async fn ancestor_state_root_prior_to_split() {
    let db_path = tempdir().unwrap();

    let spec = test_spec::<E>();

    let store_config = StoreConfig {
        prune_payloads: false,
        hierarchy_config: HierarchyConfig::from_str("5,7,8").unwrap(),
        ..StoreConfig::default()
    };
    let chain_config = ChainConfig {
        reconstruct_historic_states: false,
        ..ChainConfig::default()
    };

    let store = get_store_generic(&db_path, store_config, spec);
    let harness = get_harness_generic(
        store.clone(),
        LOW_VALIDATOR_COUNT,
        chain_config,
        NodeCustodyType::Fullnode,
    );

    // Produce blocks until we have passed through two full snapshot periods. This period length is
    // determined by the hierarchy config set above.
    let num_blocks = 2 * store
        .hierarchy
        .next_snapshot_slot(Slot::new(1))
        .unwrap()
        .as_u64();

    for num_blocks_so_far in 0..num_blocks {
        harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;
        harness.advance_slot();

        // Check that `get_ancestor_state_root` can look up the grid-aligned ancestors of every hot
        // state, even at ancestor slots prior to the split.
        let head_state = harness.get_current_state();
        assert_eq!(head_state.slot().as_u64(), num_blocks_so_far + 1);

        let split_slot = store.get_split_slot();
        let anchor_slot = store.get_anchor_info().anchor_slot;

        for state_slot in (split_slot.as_u64()..=num_blocks_so_far).map(Slot::new) {
            for ancestor_slot in store
                .hierarchy
                .closest_layer_points(state_slot, anchor_slot)
            {
                // The function currently doesn't consider a state an ancestor of itself, so this
                // does not work.
                if ancestor_slot == state_slot {
                    continue;
                }
                let ancestor_state_root = store::hot_cold_store::get_ancestor_state_root(
                    &store,
                    &head_state,
                    ancestor_slot,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "get_ancestor_state_root failed for state_slot={state_slot}, \
                         ancestor_slot={ancestor_slot}, head_slot={}. error: {e:?}",
                        head_state.slot()
                    )
                });

                // Check state root correctness.
                assert_eq!(
                    store
                        .load_hot_state_summary(&ancestor_state_root)
                        .unwrap()
                        .unwrap_or_else(|| panic!(
                            "no summary found for {ancestor_state_root:?} (slot {ancestor_slot})"
                        ))
                        .slot,
                    ancestor_slot,
                )
            }
        }
    }

    // This test only makes sense if the split is non-zero by the end.
    assert_ne!(store.get_split_slot(), 0);
}

// Test that the chain operates correctly when the split state is stored as a ReplayFrom.
#[tokio::test]
async fn replay_from_split_state() {
    let db_path = tempdir().unwrap();

    let spec = test_spec::<E>();

    let store_config = StoreConfig {
        prune_payloads: false,
        hierarchy_config: HierarchyConfig::from_str("5").unwrap(),
        ..StoreConfig::default()
    };
    let chain_config = ChainConfig {
        reconstruct_historic_states: false,
        ..ChainConfig::default()
    };

    let store = get_store_generic(&db_path, store_config.clone(), spec.clone());
    let harness = get_harness_generic(
        store.clone(),
        LOW_VALIDATOR_COUNT,
        chain_config,
        NodeCustodyType::Fullnode,
    );

    // Produce blocks until we finalize epoch 3 which will not be stored as a snapshot.
    let num_blocks = 5 * E::slots_per_epoch() as usize;

    harness
        .extend_chain(
            num_blocks,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let split = store.get_split_info();
    let anchor_slot = store.get_anchor_info().anchor_slot;
    assert_eq!(split.slot, 3 * E::slots_per_epoch());
    assert_eq!(anchor_slot, 0);
    assert!(
        store
            .hierarchy
            .storage_strategy(split.slot, anchor_slot)
            .unwrap()
            .is_replay_from()
    );

    // Close the database and reopen it.
    drop(store);
    drop(harness);

    let store = get_store_generic(&db_path, store_config, spec);

    // Check that the split state is still accessible.
    assert_eq!(store.get_split_slot(), split.slot);
    let state = store
        .get_hot_state(&split.state_root, false)
        .unwrap()
        .expect("split state should be present");
    assert_eq!(state.slot(), split.slot);
}

/// Test that regular nodes filter and store only custody columns when processing blocks with data columns.
#[tokio::test]
async fn test_custody_column_filtering_regular_node() {
    // Skip test if PeerDAS is not scheduled
    if !test_spec::<E>().is_peer_das_scheduled() {
        return;
    }

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Generate a block with data columns
    harness.execution_block_generator().set_min_blob_count(1);
    let current_slot = harness.get_current_slot();
    let block_root = harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Get custody columns for this epoch - regular nodes only store a subset
    let expected_custody_columns: HashSet<_> = harness
        .chain
        .custody_columns_for_epoch(Some(current_slot.epoch(E::slots_per_epoch())))
        .iter()
        .copied()
        .collect();

    // Check what actually got stored in the database
    let stored_column_indices: HashSet<_> = store
        .get_data_column_keys(block_root)
        .expect("should get stored column keys")
        .into_iter()
        .collect();

    assert_eq!(
        stored_column_indices, expected_custody_columns,
        "Regular node should only store custody columns"
    );
}

/// Test that supernodes store all data columns when processing blocks with data columns.
#[tokio::test]
async fn test_custody_column_filtering_supernode() {
    // Skip test if PeerDAS is not scheduled
    if !test_spec::<E>().is_peer_das_scheduled() {
        return;
    }

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness_import_all_data_columns(store.clone(), LOW_VALIDATOR_COUNT);

    // Generate a block with data columns
    harness.execution_block_generator().set_min_blob_count(1);
    let block_root = harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Supernodes are expected to store all data columns
    let expected_custody_columns: HashSet<_> = (0..E::number_of_columns() as u64).collect();

    // Check what actually got stored in the database
    let stored_column_indices: HashSet<_> = store
        .get_data_column_keys(block_root)
        .expect("should get stored column keys")
        .into_iter()
        .collect();

    assert_eq!(
        stored_column_indices, expected_custody_columns,
        "Supernode should store all custody columns"
    );
}

#[tokio::test]
async fn test_missing_columns_after_cgc_change() {
    let spec = test_spec::<E>();

    let num_validators = 8;

    let num_epochs_before_increase = 4;

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone().into())
        .deterministic_keypairs(num_validators)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let state = harness.chain.head_beacon_state_cloned();

    if !state.fork_name_unchecked().fulu_enabled() {
        return;
    }

    let custody_context = harness.chain.data_availability_checker.custody_context();

    harness.advance_slot();
    harness
        .extend_chain(
            (E::slots_per_epoch() * num_epochs_before_increase) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let epoch_before_increase = Epoch::new(num_epochs_before_increase);

    let missing_columns = harness
        .chain
        .get_missing_columns_for_epoch(epoch_before_increase);

    // We should have no missing columns
    assert_eq!(missing_columns.len(), 0);

    let epoch_after_increase = Epoch::new(num_epochs_before_increase + 2);

    let cgc_change_slot = epoch_before_increase.end_slot(E::slots_per_epoch());
    custody_context.register_validators(vec![(1, 32_000_000_000 * 9)], cgc_change_slot, &spec);

    harness.advance_slot();
    harness
        .extend_chain(
            (E::slots_per_epoch() * 5) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // We should have missing columns from before the cgc increase
    let missing_columns = harness
        .chain
        .get_missing_columns_for_epoch(epoch_before_increase);

    assert!(!missing_columns.is_empty());

    // We should have no missing columns after the cgc increase
    let missing_columns = harness
        .chain
        .get_missing_columns_for_epoch(epoch_after_increase);

    assert!(missing_columns.is_empty());
}

#[tokio::test]
async fn test_safely_backfill_data_column_custody_info() {
    let spec = test_spec::<E>();

    let num_validators = 8;

    let start_epochs = 4;

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone().into())
        .deterministic_keypairs(num_validators)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let state = harness.chain.head_beacon_state_cloned();

    if !state.fork_name_unchecked().fulu_enabled() {
        return;
    }

    let custody_context = harness.chain.data_availability_checker.custody_context();

    harness.advance_slot();
    harness
        .extend_chain(
            (E::slots_per_epoch() * start_epochs) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let epoch_before_increase = Epoch::new(start_epochs);
    let effective_delay_slots =
        CUSTODY_CHANGE_DA_EFFECTIVE_DELAY_SECONDS / harness.chain.spec.seconds_per_slot;

    let cgc_change_slot = epoch_before_increase.end_slot(E::slots_per_epoch());

    custody_context.register_validators(vec![(1, 32_000_000_000 * 16)], cgc_change_slot, &spec);

    let epoch_after_increase =
        (cgc_change_slot + effective_delay_slots).epoch(E::slots_per_epoch());

    harness.advance_slot();
    harness
        .extend_chain(
            (E::slots_per_epoch() * 5) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head_slot = harness.chain.head().snapshot.beacon_block.slot();

    harness
        .chain
        .update_data_column_custody_info(Some(head_slot));

    // We can only safely update custody column info 1 epoch at a time
    // Skipping an epoch should return an error
    harness
        .chain
        .safely_backfill_data_column_custody_info(head_slot.epoch(E::slots_per_epoch()) - 2)
        .unwrap_err();

    // Iterate from the head epoch back to 0 and try to backfill data column custody info
    for epoch in (0..head_slot.epoch(E::slots_per_epoch()).into()).rev() {
        // This is an epoch before the cgc change took into effect, we shouldnt be able to update
        // without performing custody backfill sync
        if epoch <= epoch_after_increase.into() {
            harness
                .chain
                .safely_backfill_data_column_custody_info(Epoch::new(epoch))
                .unwrap_err();
        } else {
            // This is an epoch after the cgc change took into effect, we should be able to update
            // as long as we iterate epoch by epoch
            harness
                .chain
                .safely_backfill_data_column_custody_info(Epoch::new(epoch))
                .unwrap();
            let earliest_available_epoch = harness
                .chain
                .earliest_custodied_data_column_epoch()
                .unwrap();
            assert_eq!(Epoch::new(epoch), earliest_available_epoch);
        }
    }
}

/// Checks that two chains are the same, for the purpose of these tests.
///
/// Several fields that are hard/impossible to check are ignored (e.g., the store).
fn assert_chains_pretty_much_the_same<T: BeaconChainTypes>(a: &BeaconChain<T>, b: &BeaconChain<T>) {
    assert_eq!(a.spec, b.spec, "spec should be equal");
    assert_eq!(a.op_pool, b.op_pool, "op_pool should be equal");
    let a_head = a.head_snapshot();
    let b_head = b.head_snapshot();
    assert_eq!(
        a_head.beacon_block_root, b_head.beacon_block_root,
        "head block roots should be equal"
    );
    assert_eq!(
        a_head.beacon_block, b_head.beacon_block,
        "head blocks should be equal"
    );
    // Drop all caches to prevent them messing with the equality check.
    let mut a_head_state = a_head.beacon_state.clone();
    a_head_state.drop_all_caches().unwrap();
    let mut b_head_state = b_head.beacon_state.clone();
    b_head_state.drop_all_caches().unwrap();
    assert_eq!(a_head_state, b_head_state, "head states should be equal");
    assert_eq!(a.heads(), b.heads(), "heads() should be equal");
    assert_eq!(
        a.genesis_block_root, b.genesis_block_root,
        "genesis_block_root should be equal"
    );

    let slot = a.slot().unwrap();
    let spec = T::EthSpec::default_spec();
    assert!(
        a.canonical_head
            .fork_choice_write_lock()
            .get_head(slot, &spec)
            .unwrap()
            == b.canonical_head
                .fork_choice_write_lock()
                .get_head(slot, &spec)
                .unwrap(),
        "fork_choice heads should be equal"
    );
}

/// Check that the head state's slot matches `expected_slot`.
fn check_slot(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head_snapshot().beacon_state;

    assert_eq!(
        state.slot(),
        expected_slot,
        "head should be at the current slot"
    );
}

/// Check that the chain has finalized under best-case assumptions, and check the head slot.
fn check_finalization(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head_snapshot().beacon_state;

    check_slot(harness, expected_slot);

    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );
}

/// Check that the HotColdDB's split_slot is equal to the start slot of the last finalized epoch.
fn check_split_slot(
    harness: &TestHarness,
    store: Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>>,
) {
    let split_slot = store.get_split_slot();
    assert_eq!(
        harness
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch()),
        split_slot
    );
    assert_ne!(split_slot, 0);
}

/// Check that all the states in a chain dump have the correct tree hash.
fn check_chain_dump(harness: &TestHarness, expected_len: u64) {
    check_chain_dump_from_slot(harness, Slot::new(0), expected_len)
}

fn check_chain_dump_from_slot(harness: &TestHarness, from_slot: Slot, expected_len: u64) {
    let mut chain_dump = harness.chain.chain_dump_from_slot(from_slot).unwrap();

    assert_eq!(chain_dump.len() as u64, expected_len);

    for checkpoint in &mut chain_dump {
        // Check that the tree hash of the stored state is as expected
        assert_eq!(
            checkpoint.beacon_state_root(),
            checkpoint.beacon_state.update_tree_hash_cache().unwrap(),
            "tree hash of stored state is incorrect"
        );

        // Check that looking up the state root with no slot hint succeeds.
        // This tests the state root -> slot mapping.
        assert_eq!(
            harness
                .chain
                .store
                .get_state(&checkpoint.beacon_state_root(), None, CACHE_STATE_IN_TESTS)
                .expect("no error")
                .expect("state exists")
                .slot(),
            checkpoint.beacon_state.slot()
        );

        // Check presence of execution payload on disk.
        if harness.chain.spec.bellatrix_fork_epoch.is_some() {
            assert!(
                harness
                    .chain
                    .store
                    .execution_payload_exists(&checkpoint.beacon_block_root)
                    .unwrap(),
                "incorrect payload storage for block at slot {}: {:?}",
                checkpoint.beacon_block.slot(),
                checkpoint.beacon_block_root,
            );
        }
    }

    // Check the forwards block roots iterator against the chain dump
    let chain_dump_block_roots = chain_dump
        .iter()
        .map(|checkpoint| (checkpoint.beacon_block_root, checkpoint.beacon_block.slot()))
        .collect::<Vec<_>>();

    let mut forward_block_roots = harness
        .chain
        .forwards_iter_block_roots(from_slot)
        .expect("should get iter")
        .map(Result::unwrap)
        .collect::<Vec<_>>();

    // Drop the block roots for skipped slots.
    forward_block_roots.dedup_by_key(|(block_root, _)| *block_root);

    for i in 0..std::cmp::max(chain_dump_block_roots.len(), forward_block_roots.len()) {
        assert_eq!(
            chain_dump_block_roots[i],
            forward_block_roots[i],
            "split slot is {}",
            harness.chain.store.get_split_slot()
        );
    }
}

/// Check that every state from the canonical chain is in the database, and that the
/// reverse state and block root iterators reach genesis.
fn check_iterators(harness: &TestHarness) {
    check_iterators_from_slot(harness, Slot::new(0))
}

fn check_iterators_from_slot(harness: &TestHarness, slot: Slot) {
    let mut max_slot = None;
    for (state_root, slot) in harness
        .chain
        .forwards_iter_state_roots(slot)
        .expect("should get iter")
        .map(Result::unwrap)
    {
        assert!(
            harness
                .chain
                .store
                .get_state(&state_root, Some(slot), CACHE_STATE_IN_TESTS)
                .unwrap()
                .is_some(),
            "state {:?} from canonical chain should be in DB",
            state_root
        );
        max_slot = Some(slot);
    }
    // Assert that we reached the head.
    assert_eq!(max_slot, Some(harness.head_slot()));
    // Assert that the block root iterator reaches the head.
    assert_eq!(
        harness
            .chain
            .forwards_iter_block_roots(slot)
            .expect("should get iter")
            .last()
            .map(Result::unwrap)
            .map(|(_, slot)| slot),
        Some(harness.head_slot())
    );
}

fn get_finalized_epoch_boundary_blocks(
    dump: &[BeaconSnapshot<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>],
) -> HashSet<SignedBeaconBlockHash> {
    dump.iter()
        .cloned()
        .map(|checkpoint| checkpoint.beacon_state.finalized_checkpoint().root.into())
        .collect()
}

fn get_blocks(
    dump: &[BeaconSnapshot<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>],
) -> HashSet<SignedBeaconBlockHash> {
    dump.iter()
        .cloned()
        .map(|checkpoint| checkpoint.beacon_block_root.into())
        .collect()
}

fn clone_block<E: EthSpec>(block: &AvailableBlock<E>) -> AvailableBlock<E> {
    block.__clone_without_recv().unwrap()
}
