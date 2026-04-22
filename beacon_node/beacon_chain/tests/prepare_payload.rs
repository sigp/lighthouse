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
use state_processing::per_block_processing::{
    apply_parent_execution_payload, withdrawals::get_expected_withdrawals,
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
    prepare_payload_generic(PayloadStatus::Full).await;
}

#[tokio::test]
async fn prepare_payload_on_empty_parent() {
    prepare_payload_generic(PayloadStatus::Empty).await;
}

async fn prepare_payload_generic(parent_payload_status: PayloadStatus) {
    // Post-Gloas test.
    let spec = test_spec::<E>();
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }

    let num_blocks_produced = E::slots_per_epoch() * 3;
    let parent_slot = Slot::new(num_blocks_produced) + 1;
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
    let (block_contents, opt_envelope, parent_block_state) =
        harness.make_block_with_envelope(state, parent_slot).await;
    let envelope = opt_envelope.unwrap();
    let block_root = harness
        .process_block(
            parent_slot,
            block_contents.0.canonical_root(),
            block_contents.clone(),
        )
        .await
        .unwrap();

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
    let pending_state = &cached_head.snapshot.beacon_state;
    let parent_bid = pending_state
        .latest_execution_payload_bid()
        .expect("should get latest bid");

    // Withdrawals from the empty state (without execution requests applied).
    let withdrawals_empty: Withdrawals<E> = get_expected_withdrawals(pending_state, &spec)
        .expect("should get pending withdrawals")
        .into();

    // Withdrawals from the Full state (with execution requests applied).
    let mut full_state = pending_state.clone();
    apply_parent_execution_payload(
        &mut full_state,
        parent_bid,
        &envelope.message.execution_requests,
        &spec,
    )
    .expect("should apply parent execution payload");
    let withdrawals_full: Withdrawals<E> = get_expected_withdrawals(&full_state, &spec)
        .expect("should get full withdrawals")
        .into();

    assert_ne!(
        withdrawals_empty, withdrawals_full,
        "Applying execution requests should change the expected withdrawals"
    );

    // Call `prepare_beacon_proposer` for the next slot and ensure that it primes the execution
    // layer payload attributes cache with the correct withdrawals (the ones taking into account
    // the applied execution_requests).
    let current_slot = harness.chain.slot().expect("should get slot");
    let prepare_slot = current_slot + 1;
    let proposer_index = pending_state
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
        withdrawals_full.to_vec()
    } else {
        withdrawals_empty.to_vec()
    };

    assert_eq!(
        actual_withdrawals, &expected_withdrawals,
        "prepare_beacon_proposer should use withdrawals computed from the \
         {parent_payload_status:?} state"
    );
}
