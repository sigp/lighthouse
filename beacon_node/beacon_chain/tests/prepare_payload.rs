#![cfg(not(debug_assertions))]
#![allow(clippy::result_large_err)]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType, test_spec,
};
use beacon_chain::{ChainConfig, custody_context::NodeCustodyType};
use bls::Keypair;
use eth2::types::ProposerPreparationData;
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
    let spec = test_spec::<E>();
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }

    let num_blocks_produced = E::slots_per_epoch() * 3;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let chain_config = ChainConfig {
        archive: true,
        ..ChainConfig::default()
    };
    let harness = get_harness_generic(
        store.clone(),
        LOW_VALIDATOR_COUNT,
        chain_config,
        NodeCustodyType::Fullnode,
    );

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
    // This requires injecting at least one valid and actionable consolidation request
    // (switch-to-compounding) into the execution requests. A switch-to-compounding request
    // changes a validator's withdrawal credentials from 0x01 (eth1) to 0x02 (compounding),
    // which reduces their balance to min_activation_balance and queues the excess as a
    // pending deposit. This removes the validator from the partial withdrawal sweep.
    //
    // We target an odd-indexed validator since odd validators are created with eth1 withdrawal
    // credentials in the interop genesis builder.
    let target_validator_index = 1_usize;
    let head_state = &harness
        .chain
        .canonical_head
        .cached_head()
        .snapshot
        .beacon_state;
    let validator = head_state
        .get_validator(target_validator_index)
        .expect("validator should exist");

    // Sanity check: the validator has eth1 withdrawal credentials (0x01 prefix).
    assert!(
        validator.has_eth1_withdrawal_credential(&spec),
        "validator {target_validator_index} should have eth1 withdrawal credentials"
    );
    // Sanity check: the validator is partially withdrawable (has excess balance from
    // attestation rewards after 1 epoch).
    let balance = head_state
        .get_balance(target_validator_index)
        .expect("should get balance");
    assert!(
        balance > spec.min_activation_balance,
        "validator should have excess balance from attestation rewards: balance={balance}, \
         min_activation_balance={}",
        spec.min_activation_balance
    );

    let source_address = validator
        .get_execution_withdrawal_address(&spec)
        .expect("validator should have execution withdrawal address");

    let consolidation_request = ConsolidationRequest {
        source_address,
        source_pubkey: validator.pubkey,
        target_pubkey: validator.pubkey,
    };

    let execution_requests = ExecutionRequests::<E> {
        deposits: VariableList::empty(),
        withdrawals: VariableList::empty(),
        consolidations: VariableList::new(vec![consolidation_request])
            .expect("should create consolidation requests list"),
    };

    // Inject the execution requests into the mock EL so the next payload includes them.
    harness
        .execution_block_generator()
        .set_next_execution_requests(execution_requests);

    // Produce and import one more block. Its envelope will contain the consolidation request.
    harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Verify that the withdrawals computed from the block's state differ from the withdrawals
    // computed from the block's state with its payload applied by
    // `apply_parent_execution_payload`.
    let cached_head = harness.chain.canonical_head.cached_head();
    let pending_state = &cached_head.snapshot.beacon_state;
    let envelope = cached_head
        .snapshot
        .execution_envelope
        .as_ref()
        .expect("head should have execution envelope (Full status)");
    let parent_bid = pending_state
        .latest_execution_payload_bid()
        .expect("should get latest bid");

    // Withdrawals from the Pending state (without execution requests applied).
    let withdrawals_pending: Withdrawals<E> = get_expected_withdrawals(pending_state, &spec)
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
        withdrawals_pending, withdrawals_full,
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

    // Extract the payload attributes that were sent to the EL via forkchoiceUpdated.
    let mock_el = harness
        .mock_execution_layer
        .as_ref()
        .expect("should have mock execution layer");
    let previous_request = mock_el
        .server
        .take_previous_request()
        .expect("should have a previous forkchoiceUpdated request");
    let params = previous_request
        .get("params")
        .expect("should have params field");
    let payload_attributes_json = params.get(1).expect("should have payload attributes param");

    // The payload attributes should be V4 for Gloas.
    let attributes: execution_layer::json_structures::JsonPayloadAttributesV4 =
        serde_json::from_value(payload_attributes_json.clone())
            .expect("should deserialize V4 payload attributes");

    let actual_withdrawals: Vec<Withdrawal> =
        attributes.withdrawals.into_iter().map(Into::into).collect();
    let expected_withdrawals: Vec<Withdrawal> = withdrawals_full.to_vec();

    assert_eq!(
        actual_withdrawals, expected_withdrawals,
        "prepare_beacon_proposer should use withdrawals computed from the Full state \
         (with execution requests applied)"
    );
}
