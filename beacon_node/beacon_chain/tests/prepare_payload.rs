#![cfg(not(debug_assertions))]
#![allow(clippy::result_large_err)]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType, test_spec,
};
use beacon_chain::{ChainConfig, custody_context::NodeCustodyType};
use bls::Keypair;
use eth2::types::ProposerPreparationData;
use fork_choice::PayloadStatus;
use logging::create_test_tracing_subscriber;
use ssz_types::VariableList;
use state_processing::{
    per_block_processing::{apply_parent_execution_payload, withdrawals::get_expected_withdrawals},
    state_advance::complete_state_advance,
};
use std::sync::{Arc, LazyLock};
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tempfile::{TempDir, tempdir};
use types::*;

// Should ideally be divisible by 3.
pub const LOW_VALIDATOR_COUNT: usize = 32;
pub const HIGH_VALIDATOR_COUNT: usize = 64;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(HIGH_VALIDATOR_COUNT));

type E = MinimalEthSpec;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;

fn get_store(
    db_path: &TempDir,
    spec: Arc<ChainSpec>,
) -> Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>> {
    let store_config = StoreConfig {
        prune_payloads: false,
        ..StoreConfig::default()
    };
    get_store_generic(db_path, store_config, spec)
}

fn get_store_generic(
    db_path: &TempDir,
    config: StoreConfig,
    spec: Arc<ChainSpec>,
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
        spec,
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
async fn prepare_payload_on_full_parent_next_slot() {
    prepare_payload_generic(
        PayloadStatus::Full,
        Slot::new(3 * E::slots_per_epoch() + 1),
        Slot::new(3 * E::slots_per_epoch() + 2),
    )
    .await;
}

#[tokio::test]
async fn prepare_payload_on_full_parent_one_epoch_skip() {
    prepare_payload_generic(
        PayloadStatus::Full,
        Slot::new(3 * E::slots_per_epoch() + 1),
        Slot::new(4 * E::slots_per_epoch()),
    )
    .await;
}

#[tokio::test]
async fn prepare_payload_on_full_parent_uneven_one_epoch_skip() {
    prepare_payload_generic(
        PayloadStatus::Full,
        Slot::new(3 * E::slots_per_epoch() + 1),
        Slot::new(5 * E::slots_per_epoch() - 1),
    )
    .await;
}

#[tokio::test]
async fn prepare_payload_on_empty_parent_next_slot() {
    prepare_payload_generic(
        PayloadStatus::Empty,
        Slot::new(3 * E::slots_per_epoch() + 1),
        Slot::new(3 * E::slots_per_epoch() + 2),
    )
    .await;
}

#[tokio::test]
async fn prepare_payload_on_empty_parent_one_epoch_skip() {
    prepare_payload_generic(
        PayloadStatus::Empty,
        Slot::new(3 * E::slots_per_epoch() + 1),
        Slot::new(4 * E::slots_per_epoch()),
    )
    .await;
}

async fn prepare_payload_generic(
    parent_payload_status: PayloadStatus,
    parent_block_slot: Slot,
    prepare_slot: Slot,
) {
    assert!(parent_block_slot > 0);

    // Post-Gloas test.
    let spec = Arc::new(test_spec::<E>());
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }

    let num_blocks_produced = parent_block_slot.as_u64() - 1;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path, spec.clone());
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Advance the slot so the next extend_chain produces at a fresh slot.
    harness.advance_slot();

    // Produce a block with a payload that affects withdrawals for the next slot.
    // A switch-to-compounding consolidation changes withdrawal credentials from 0x01 to 0x02,
    // which queues the validator's excess balance as a pending deposit and removes it from the
    // partial withdrawal sweep. We target an odd-indexed validator since odd validators are
    // created with eth1 withdrawal credentials in the interop genesis builder.
    let consolidation_request = harness.make_switch_to_compounding_request(1);

    let execution_requests = ExecutionRequests::<E> {
        deposits: VariableList::empty(),
        withdrawals: VariableList::empty(),
        consolidations: VariableList::new(vec![consolidation_request]).unwrap(),
    };

    // Inject the execution requests into the mock EL so the next payload includes them.
    harness
        .execution_block_generator()
        .set_next_execution_requests(execution_requests);

    // Produce and import one more block. Its envelope will contain the consolidation request.
    // TODO(gloas): all this ugly plumbing could be avoided with some more "implicit" context
    // methods
    let state = harness.get_current_state();
    let (block_contents, opt_envelope, parent_block_state) = harness
        .make_block_with_envelope(state, parent_block_slot)
        .await;
    let envelope = opt_envelope.unwrap();
    let block_root = harness
        .process_block(
            parent_block_slot,
            block_contents.0.canonical_root(),
            block_contents.clone(),
        )
        .await
        .unwrap();

    // TODO(gloas): try a case where head is empty even though envelope is processed
    if parent_payload_status == PayloadStatus::Full {
        harness
            .process_envelope(
                block_root.into(),
                envelope.clone(),
                &parent_block_state,
                block_contents.0.state_root(),
            )
            .await;
    }

    // Verify that the withdrawals computed from the block's state differ from the withdrawals
    // computed from the block's state with its payload applied by
    // `apply_parent_execution_payload`.
    let cached_head = harness.chain.canonical_head.cached_head();
    let unadvanced_empty_state = &cached_head.snapshot.beacon_state;

    let mut advanced_empty_state = unadvanced_empty_state.clone();
    complete_state_advance(&mut advanced_empty_state, None, prepare_slot, &spec).unwrap();

    let mut unadvanced_full_state = unadvanced_empty_state.clone();
    apply_parent_execution_payload(
        &mut unadvanced_full_state,
        &envelope.message.execution_requests,
        &spec,
    )
    .unwrap();

    let mut advanced_full_state = advanced_empty_state.clone();
    apply_parent_execution_payload(
        &mut advanced_full_state,
        &envelope.message.execution_requests,
        &spec,
    )
    .unwrap();

    let withdrawals_unadvanced_empty: Withdrawals<E> =
        get_expected_withdrawals(unadvanced_empty_state, &spec)
            .unwrap()
            .into();
    let withdrawals_advanced_empty: Withdrawals<E> =
        get_expected_withdrawals(&advanced_empty_state, &spec)
            .unwrap()
            .into();
    let withdrawals_unadvanced_full: Withdrawals<E> =
        get_expected_withdrawals(&unadvanced_full_state, &spec)
            .unwrap()
            .into();
    let withdrawals_advanced_full: Withdrawals<E> =
        get_expected_withdrawals(&advanced_full_state, &spec)
            .unwrap()
            .into();

    assert_ne!(
        withdrawals_advanced_empty, withdrawals_advanced_full,
        "Applying execution requests should change the expected withdrawals"
    );

    let expect_state_advance_to_change_withdrawals =
        prepare_slot.epoch(E::slots_per_epoch()) > parent_block_slot.epoch(E::slots_per_epoch());
    if expect_state_advance_to_change_withdrawals {
        if parent_payload_status == fork_choice::PayloadStatus::Full {
            assert_ne!(
                withdrawals_unadvanced_full, withdrawals_advanced_full,
                "Advancing the state should change the withdrawals"
            );
        } else {
            assert_ne!(
                withdrawals_unadvanced_empty, withdrawals_advanced_empty,
                "Advancing the state should change the withdrawals"
            );
        }
    }

    // Call `prepare_beacon_proposer` for the next slot and ensure that it primes the execution
    // layer payload attributes cache with the correct withdrawals (the ones taking into account
    // the applied execution_requests).
    let current_slot = prepare_slot - 1;
    let proposer_index = advanced_empty_state
        .get_beacon_proposer_index(prepare_slot, &spec)
        .expect("should get proposer index");

    // Register the proposer so prepare_beacon_proposer doesn't skip it.
    let el = harness.chain.execution_layer.as_ref().unwrap();
    el.update_proposer_preparation(
        prepare_slot.epoch(E::slots_per_epoch()),
        [(
            &ProposerPreparationData {
                validator_index: proposer_index as u64,
                fee_recipient: Address::repeat_byte(42),
            },
            &None,
        )],
    )
    .await;

    // Advance the slot clock to just before the prepare slot so the lookahead check passes.
    harness.advance_to_slot_lookahead(prepare_slot, harness.chain.config.prepare_payload_lookahead);

    harness
        .chain
        .prepare_beacon_proposer(current_slot)
        .await
        .expect("prepare_beacon_proposer should succeed");

    // Read the payload attributes from the EL cache and verify the withdrawals.
    let el = harness.chain.execution_layer.as_ref().unwrap();
    let head_root = harness.head_block_root();
    let attributes = el
        .payload_attributes(prepare_slot, head_root, parent_payload_status)
        .await
        .expect("should have cached payload attributes for prepare_slot");

    let actual_withdrawals = attributes.withdrawals().unwrap();
    let expected_withdrawals: Vec<Withdrawal> = if parent_payload_status == PayloadStatus::Full {
        withdrawals_advanced_full.to_vec()
    } else {
        withdrawals_advanced_empty.to_vec()
    };

    assert_eq!(
        actual_withdrawals, &expected_withdrawals,
        "prepare_beacon_proposer should use withdrawals computed from the \
         {parent_payload_status:?} state"
    );
}

#[tokio::test]
async fn prepare_payload_on_genesis_next_slot() {
    prepare_payload_on_genesis_generic(Slot::new(1)).await;
}

#[tokio::test]
async fn prepare_payload_on_genesis_skip_two_epochs() {
    prepare_payload_on_genesis_generic(Slot::new(2 * E::slots_per_epoch())).await;
}

async fn prepare_payload_on_genesis_generic(prepare_slot: Slot) {
    // Post-Gloas test.
    let spec = Arc::new(test_spec::<E>());
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }

    // Genesis is always considered Empty.
    let parent_payload_status = PayloadStatus::Empty;

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path, spec.clone());
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // At genesis withdrawals are empty (because nothing has happened yet), so we don't assert
    // anything about the advanced vs unadvanced state. This test just exists to test that
    // calculating payload attributes at genesis works and doesn't error.
    let cached_head = harness.chain.canonical_head.cached_head();
    let unadvanced_state = &cached_head.snapshot.beacon_state;

    let mut advanced_state = unadvanced_state.clone();
    complete_state_advance(&mut advanced_state, None, prepare_slot, &spec).unwrap();

    let withdrawals_advanced: Withdrawals<E> = get_expected_withdrawals(&advanced_state, &spec)
        .unwrap()
        .into();

    // Call `prepare_beacon_proposer` for the next slot and ensure that it primes the execution
    // layer payload attributes cache with the correct withdrawals (the ones taking into account
    // the state advance).
    let current_slot = prepare_slot - 1;
    let proposer_index = advanced_state
        .get_beacon_proposer_index(prepare_slot, &spec)
        .unwrap();

    // Register the proposer so prepare_beacon_proposer doesn't skip it.
    let el = harness.chain.execution_layer.as_ref().unwrap();
    el.update_proposer_preparation(
        prepare_slot.epoch(E::slots_per_epoch()),
        [(
            &ProposerPreparationData {
                validator_index: proposer_index as u64,
                fee_recipient: Address::repeat_byte(42),
            },
            &None,
        )],
    )
    .await;

    // Advance the slot clock to just before the prepare slot so the lookahead check passes.
    harness.advance_to_slot_lookahead(prepare_slot, harness.chain.config.prepare_payload_lookahead);

    harness
        .chain
        .prepare_beacon_proposer(current_slot)
        .await
        .unwrap();

    // Read the payload attributes from the EL cache and verify the withdrawals.
    let el = harness.chain.execution_layer.as_ref().unwrap();
    let head_root = harness.head_block_root();
    let attributes = el
        .payload_attributes(prepare_slot, head_root, parent_payload_status)
        .await
        .unwrap();

    let actual_withdrawals = attributes.withdrawals().unwrap();
    let expected_withdrawals: Vec<Withdrawal> = withdrawals_advanced.to_vec();

    assert_eq!(
        actual_withdrawals, &expected_withdrawals,
        "prepare_beacon_proposer should use withdrawals computed from the \
         {parent_payload_status:?} advanced genesis state"
    );
    assert!(actual_withdrawals.is_empty());
}

#[tokio::test]
async fn prepare_payload_on_fork_boundary_no_skip() {
    prepare_payload_on_fork_boundary(
        Slot::new(2 * E::slots_per_epoch()) - 1,
        Slot::new(2 * E::slots_per_epoch()),
        Epoch::new(2),
    )
    .await;
}

#[tokio::test]
async fn prepare_payload_on_fork_boundary_skip_one_prior() {
    prepare_payload_on_fork_boundary(
        Slot::new(2 * E::slots_per_epoch()) - 2,
        Slot::new(2 * E::slots_per_epoch()),
        Epoch::new(2),
    )
    .await;
}

#[tokio::test]
async fn prepare_payload_on_fork_boundary_skip_one_after() {
    prepare_payload_on_fork_boundary(
        Slot::new(2 * E::slots_per_epoch()) - 1,
        Slot::new(2 * E::slots_per_epoch()) + 1,
        Epoch::new(2),
    )
    .await;
}

#[tokio::test]
async fn prepare_payload_on_fork_boundary_skip_whole_epoch() {
    prepare_payload_on_fork_boundary(
        Slot::new(E::slots_per_epoch()),
        Slot::new(2 * E::slots_per_epoch()),
        Epoch::new(2),
    )
    .await;
}

async fn prepare_payload_on_fork_boundary(
    parent_block_slot: Slot,
    prepare_slot: Slot,
    gloas_fork_epoch: Epoch,
) {
    // Post-Gloas test.
    let mut spec = test_spec::<E>();
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }
    spec.gloas_fork_epoch = Some(gloas_fork_epoch);
    let spec = Arc::new(spec);

    // Pre-Gloas blocks are always considered Empty.
    let parent_payload_status = PayloadStatus::Empty;

    let num_blocks_produced = parent_block_slot.as_u64();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path, spec.clone());
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Verify that the withdrawals computed from the block's state differ from the withdrawals
    // computed from the block's state with its payload applied by
    // `apply_parent_execution_payload`.
    let cached_head = harness.chain.canonical_head.cached_head();
    let unadvanced_state = &cached_head.snapshot.beacon_state;

    let mut advanced_state = unadvanced_state.clone();
    complete_state_advance(&mut advanced_state, None, prepare_slot, &spec).unwrap();

    let withdrawals_unadvanced: Withdrawals<E> = get_expected_withdrawals(unadvanced_state, &spec)
        .unwrap()
        .into();
    let withdrawals_advanced: Withdrawals<E> = get_expected_withdrawals(&advanced_state, &spec)
        .unwrap()
        .into();

    let expect_state_advance_to_change_withdrawals = prepare_slot.epoch(E::slots_per_epoch()) > 0;
    if expect_state_advance_to_change_withdrawals {
        assert_ne!(
            withdrawals_unadvanced, withdrawals_advanced,
            "Advancing the state should change the withdrawals"
        );
    }

    // Call `prepare_beacon_proposer` for the next slot and ensure that it primes the execution
    // layer payload attributes cache with the correct withdrawals (the ones taking into account
    // the applied execution_requests).
    let current_slot = prepare_slot - 1;
    let proposer_index = advanced_state
        .get_beacon_proposer_index(prepare_slot, &spec)
        .unwrap();

    // Register the proposer so prepare_beacon_proposer doesn't skip it.
    let el = harness.chain.execution_layer.as_ref().unwrap();
    el.update_proposer_preparation(
        prepare_slot.epoch(E::slots_per_epoch()),
        [(
            &ProposerPreparationData {
                validator_index: proposer_index as u64,
                fee_recipient: Address::repeat_byte(42),
            },
            &None,
        )],
    )
    .await;

    // Advance the slot clock to just before the prepare slot so the lookahead check passes.
    harness.advance_to_slot_lookahead(prepare_slot, harness.chain.config.prepare_payload_lookahead);

    harness
        .chain
        .prepare_beacon_proposer(current_slot)
        .await
        .unwrap();

    // Read the payload attributes from the EL cache and verify the withdrawals.
    let el = harness.chain.execution_layer.as_ref().unwrap();
    let head_root = harness.head_block_root();
    let attributes = el
        .payload_attributes(prepare_slot, head_root, parent_payload_status)
        .await
        .unwrap();

    let actual_withdrawals = attributes.withdrawals().unwrap();
    let expected_withdrawals: Vec<Withdrawal> = withdrawals_advanced.to_vec();

    assert_eq!(
        actual_withdrawals, &expected_withdrawals,
        "prepare_beacon_proposer should use withdrawals computed from the \
         advanced state"
    );
}

#[tokio::test]
async fn gloas_block_production_caches_blobs_for_column_publishing() {
    use beacon_chain::ProduceBlockVerification;
    use beacon_chain::graffiti_calculator::GraffitiSettings;
    use eth2::types::GraffitiPolicy;

    let spec = Arc::new(test_spec::<E>());
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path, spec.clone());
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Configure the mock EL to produce at least 1 blob per block.
    harness.execution_block_generator().set_min_blob_count(1);

    // Extend the chain a few slots to get past genesis.
    harness
        .extend_chain(
            (E::slots_per_epoch() as usize) + 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    harness.advance_slot();
    let slot = harness.get_current_slot();

    // Produce a Gloas block directly via produce_block_on_state_gloas so we can
    // inspect the pending cache before it's consumed.
    let mut state = harness.get_current_state();
    complete_state_advance(&mut state, None, slot, &spec).unwrap();
    state.build_caches(&spec).unwrap();

    let proposer_index = state.get_beacon_proposer_index(slot, &spec).unwrap();
    let randao_reveal = harness.sign_randao_reveal(&state, proposer_index, slot);

    let (parent_payload_status, parent_envelope) = {
        let head = harness.chain.canonical_head.cached_head();
        (
            head.head_payload_status(),
            head.snapshot.execution_envelope.clone(),
        )
    };

    let graffiti_settings = GraffitiSettings::new(
        Some(Graffiti::default()),
        Some(GraffitiPolicy::PreserveUserGraffiti),
    );

    let (_block, _post_state, _value) = harness
        .chain
        .produce_block_on_state_gloas(
            state,
            None,
            parent_payload_status,
            parent_envelope,
            slot,
            randao_reveal,
            graffiti_settings,
            ProduceBlockVerification::VerifyRandao,
            None,
        )
        .await
        .unwrap();

    // The envelope + blobs should now be in the pending cache.
    assert!(
        harness
            .chain
            .pending_payload_envelopes
            .read()
            .contains(slot),
        "Pending cache should contain an envelope for the produced slot"
    );

    // Take the blobs from the cache — this is what publish_execution_payload_envelope does.
    let blobs = harness
        .chain
        .pending_payload_envelopes
        .write()
        .take_blobs(slot);

    assert!(
        blobs.is_some(),
        "Blobs should be cached alongside the envelope"
    );

    let blobs = blobs.unwrap();
    assert!(
        !blobs.is_empty(),
        "Blobs should be non-empty when min_blob_count >= 1"
    );

    // Verify take_blobs is consume-once.
    let second_take = harness
        .chain
        .pending_payload_envelopes
        .write()
        .take_blobs(slot);
    assert!(
        second_take.is_none(),
        "Blobs should only be consumable once"
    );

    // The envelope should still be in the cache after taking blobs.
    assert!(
        harness
            .chain
            .pending_payload_envelopes
            .read()
            .get(slot)
            .is_some(),
        "Envelope should remain in cache after taking blobs"
    );
}
