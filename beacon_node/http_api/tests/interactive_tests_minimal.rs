//! Interactive `InteractiveApiTester` tests that only run under the minimal spec.
//!
//! These live in a dedicated module (included only by `spec_minimal.rs`) so they don't need
//! per-test `#[cfg(feature = "spec-minimal")]` gating.
use beacon_chain::ChainConfig;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::test_utils::{
    AttestationStrategy, BlockStrategy, LightClientStrategy, SyncCommitteeStrategy, test_spec,
};
use eth2::types::StateId;
use http_api::test_utils::InteractiveTester;
use types::{Epoch, ForkName, Slot, Spec};

// Test that state lookups by root function correctly for states that are finalized but still
// present in the hot database, and have had their block pruned from fork choice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_by_root_pruned_from_fork_choice() {
    let validator_count = 24;
    // TODO(heze): use `ForkName::latest()` once Heze block production is wired up.
    let spec = ForkName::Gloas.make_genesis_spec(Spec::default_spec());

    let tester = InteractiveTester::new_with_initializer_and_mutator(
        Some(spec.clone()),
        validator_count,
        Some(Box::new(move |builder| {
            builder
                .deterministic_keypairs(validator_count)
                .fresh_ephemeral_store()
                .chain_config(ChainConfig {
                    epochs_per_migration: 1024,
                    ..ChainConfig::default()
                })
        })),
        None,
        Default::default(),
        false,
        NodeCustodyType::Fullnode,
    )
    .await;

    let client = &tester.client;
    let harness = &tester.harness;

    // Create some chain depth and finalize beyond fork choice's pruning depth.
    let num_epochs = 8_u64;
    let num_initial = num_epochs * Spec::slots_per_epoch();
    harness.advance_slot();
    harness
        .extend_chain_with_sync(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
            SyncCommitteeStrategy::NoValidators,
            LightClientStrategy::Disabled,
        )
        .await;

    // Should now be finalized.
    let finalized_epoch = harness.finalized_checkpoint().epoch;
    assert_eq!(finalized_epoch, num_epochs - 2);

    // The split slot should still be at 0.
    assert_eq!(harness.chain.store.get_split_slot(), 0);

    // States that are between the split and the finalized slot should be able to be looked up by
    // state root.
    for slot in 0..finalized_epoch.start_slot(Spec::slots_per_epoch()).as_u64() {
        let state_root = harness
            .chain
            .state_root_at_slot(Slot::new(slot))
            .unwrap()
            .unwrap();
        let response = client
            .get_debug_beacon_states(StateId::Root(state_root))
            .await
            .unwrap()
            .unwrap();

        assert!(response.metadata().finalized.unwrap());
        assert!(!response.metadata().execution_optimistic.unwrap());

        let mut state = response.into_data();
        assert_eq!(state.update_tree_hash_cache().unwrap(), state_root);
    }
}

// TODO(spec-gates): This test should be made spec-agnostic.
// Test that post-Fulu, v1 and v2 proposer duties return different dependent roots.
// Post-Fulu, the true dependent root shifts to the block root at the end of epoch N-2 (due to
// `min_seed_lookahead`), while the legacy v1 root remains at the end of epoch N-1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proposer_duties_v2_post_fulu_dependent_root() {
    let spec = test_spec();

    if !spec.is_fulu_scheduled() {
        return;
    }

    let validator_count = 24;
    let slots_per_epoch = Spec::slots_per_epoch();

    let tester = InteractiveTester::new(Some(spec.clone()), validator_count).await;
    let harness = &tester.harness;
    let client = &tester.client;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();
    mock_el.server.all_payloads_valid();

    // Build 3 full epochs of chain so we're in epoch 3.
    let num_slots = 3 * slots_per_epoch;
    harness.advance_slot();
    harness
        .extend_chain_with_sync(
            num_slots as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
            SyncCommitteeStrategy::AllValidators,
            LightClientStrategy::Disabled,
        )
        .await;

    let current_epoch = harness.chain.epoch().unwrap();
    assert_eq!(current_epoch, Epoch::new(3));

    // For epoch 3 with min_seed_lookahead=1:
    //   Post-Fulu decision slot: end of epoch N-2 = end of epoch 1 = slot 15
    //   Legacy decision slot:    end of epoch N-1 = end of epoch 2 = slot 23
    let true_decision_slot = Epoch::new(1).end_slot(slots_per_epoch);
    let legacy_decision_slot = Epoch::new(2).end_slot(slots_per_epoch);
    assert_eq!(true_decision_slot, Slot::new(15));
    assert_eq!(legacy_decision_slot, Slot::new(23));

    // Fetch the block roots at these slots to compute expected dependent roots.
    let expected_v2_root = harness
        .chain
        .block_root_at_slot(true_decision_slot, beacon_chain::WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();
    let expected_v1_root = harness
        .chain
        .block_root_at_slot(legacy_decision_slot, beacon_chain::WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();

    // Sanity check: the two roots should be different since they refer to different blocks.
    assert_ne!(
        expected_v1_root, expected_v2_root,
        "legacy and true decision roots should differ post-Fulu"
    );

    // Query v1 and v2 proposer duties for the current epoch.
    let v1_result = client
        .get_validator_duties_proposer(current_epoch)
        .await
        .unwrap();
    let v2_result = client
        .get_validator_duties_proposer_v2(current_epoch)
        .await
        .unwrap();

    // The proposer assignments (data) must be identical.
    assert_eq!(v1_result.data, v2_result.data);

    // The dependent roots must differ.
    assert_ne!(
        v1_result.dependent_root, v2_result.dependent_root,
        "v1 and v2 dependent roots should differ post-Fulu"
    );

    // Verify each root matches the expected value.
    assert_eq!(
        v1_result.dependent_root, expected_v1_root,
        "v1 dependent root should be block root at end of epoch N-1"
    );
    assert_eq!(
        v2_result.dependent_root, expected_v2_root,
        "v2 dependent root should be block root at end of epoch N-2"
    );

    // Also verify the next-epoch path (epoch 4).
    let next_epoch = current_epoch + 1;
    let v1_next = client
        .get_validator_duties_proposer(next_epoch)
        .await
        .unwrap();
    let v2_next = client
        .get_validator_duties_proposer_v2(next_epoch)
        .await
        .unwrap();

    assert_eq!(v1_next.data, v2_next.data);
    assert_ne!(
        v1_next.dependent_root, v2_next.dependent_root,
        "v1 and v2 next-epoch dependent roots should differ post-Fulu"
    );

    // For epoch 4: true decision is end of epoch 2 (slot 23), legacy is end of epoch 3 (slot 31).
    let expected_v2_next_root = harness
        .chain
        .block_root_at_slot(
            Epoch::new(2).end_slot(slots_per_epoch),
            beacon_chain::WhenSlotSkipped::Prev,
        )
        .unwrap()
        .unwrap();
    let expected_v1_next_root = harness
        .chain
        .block_root_at_slot(
            Epoch::new(3).end_slot(slots_per_epoch),
            beacon_chain::WhenSlotSkipped::Prev,
        )
        .unwrap()
        .unwrap_or(harness.head_block_root());
    assert_eq!(v1_next.dependent_root, expected_v1_next_root);
    assert_eq!(v2_next.dependent_root, expected_v2_next_root);
    assert_ne!(expected_v2_next_root, harness.head_block_root());
}
