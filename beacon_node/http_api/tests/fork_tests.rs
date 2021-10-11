//! Tests for API behaviour across fork boundaries.
use crate::common::*;
use beacon_chain::{test_utils::RelativeSyncCommittee, StateSkipConfig};
use eth2::types::{StateId, SyncSubcommittee};
use types::{ChainSpec, Epoch, EthSpec, MinimalEthSpec, Slot};

type E = MinimalEthSpec;

fn altair_spec(altair_fork_epoch: Epoch) -> ChainSpec {
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_committee_duties_across_fork() {
    let validator_count = E::sync_committee_size();
    let fork_epoch = Epoch::new(8);
    let spec = altair_spec(fork_epoch);
    let tester = InteractiveTester::<E>::new(Some(spec.clone()), validator_count).await;
    let harness = &tester.harness;
    let client = &tester.client;

    let all_validators = harness.get_all_validators();
    let all_validators_u64 = all_validators.iter().map(|x| *x as u64).collect::<Vec<_>>();

    assert_eq!(harness.get_current_slot(), 0);

    // Prior to the fork the endpoint should return an empty vec.
    let early_duties = client
        .post_validator_duties_sync(fork_epoch - 1, &all_validators_u64)
        .await
        .unwrap()
        .data;
    assert!(early_duties.is_empty());

    // If there's a skip slot at the fork slot, the endpoint should return duties, even
    // though the head state hasn't transitioned yet.
    let fork_slot = fork_epoch.start_slot(E::slots_per_epoch());
    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    let (_, state) = harness
        .add_attested_block_at_slot(
            fork_slot - 1,
            genesis_state,
            genesis_state_root,
            &all_validators,
        )
        .unwrap();

    harness.advance_slot();
    assert_eq!(harness.get_current_slot(), fork_slot);

    let sync_duties = client
        .post_validator_duties_sync(fork_epoch, &all_validators_u64)
        .await
        .unwrap()
        .data;
    assert_eq!(sync_duties.len(), E::sync_committee_size());

    // After applying a block at the fork slot the duties should remain unchanged.
    let state_root = state.canonical_root();
    harness
        .add_attested_block_at_slot(fork_slot, state, state_root, &all_validators)
        .unwrap();

    assert_eq!(
        client
            .post_validator_duties_sync(fork_epoch, &all_validators_u64)
            .await
            .unwrap()
            .data,
        sync_duties
    );

    // Sync duties should also be available for the next period.
    let current_period = fork_epoch.sync_committee_period(&spec).unwrap();
    let next_period_epoch = spec.epochs_per_sync_committee_period * (current_period + 1);

    let next_period_duties = client
        .post_validator_duties_sync(next_period_epoch, &all_validators_u64)
        .await
        .unwrap()
        .data;
    assert_eq!(next_period_duties.len(), E::sync_committee_size());

    // Sync duties should *not* be available for the period after the next period.
    // We expect a 400 (bad request) response.
    let next_next_period_epoch = spec.epochs_per_sync_committee_period * (current_period + 2);
    assert_eq!(
        client
            .post_validator_duties_sync(next_next_period_epoch, &all_validators_u64)
            .await
            .unwrap_err()
            .status()
            .unwrap(),
        400
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attestations_across_fork_with_skip_slots() {
    let validator_count = E::sync_committee_size();
    let fork_epoch = Epoch::new(8);
    let spec = altair_spec(fork_epoch);
    let tester = InteractiveTester::<E>::new(Some(spec.clone()), validator_count).await;
    let harness = &tester.harness;
    let client = &tester.client;

    let all_validators = harness.get_all_validators();

    let fork_slot = fork_epoch.start_slot(E::slots_per_epoch());
    let fork_state = harness
        .chain
        .state_at_slot(fork_slot, StateSkipConfig::WithStateRoots)
        .unwrap();

    harness.set_current_slot(fork_slot);

    let attestations = harness.make_attestations(
        &all_validators,
        &fork_state,
        fork_state.canonical_root(),
        (*fork_state.get_block_root(fork_slot - 1).unwrap()).into(),
        fork_slot,
    );

    let unaggregated_attestations = attestations
        .iter()
        .flat_map(|(atts, _)| atts.iter().map(|(att, _)| att.clone()))
        .collect::<Vec<_>>();

    assert!(!unaggregated_attestations.is_empty());
    client
        .post_beacon_pool_attestations(&unaggregated_attestations)
        .await
        .unwrap();

    let signed_aggregates = attestations
        .into_iter()
        .filter_map(|(_, op_aggregate)| op_aggregate)
        .collect::<Vec<_>>();
    assert!(!signed_aggregates.is_empty());

    client
        .post_validator_aggregate_and_proof(&signed_aggregates)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_contributions_across_fork_with_skip_slots() {
    let validator_count = E::sync_committee_size();
    let fork_epoch = Epoch::new(8);
    let spec = altair_spec(fork_epoch);
    let tester = InteractiveTester::<E>::new(Some(spec.clone()), validator_count).await;
    let harness = &tester.harness;
    let client = &tester.client;

    let fork_slot = fork_epoch.start_slot(E::slots_per_epoch());
    let fork_state = harness
        .chain
        .state_at_slot(fork_slot, StateSkipConfig::WithStateRoots)
        .unwrap();

    harness.set_current_slot(fork_slot);

    let sync_messages = harness.make_sync_contributions(
        &fork_state,
        *fork_state.get_block_root(fork_slot - 1).unwrap(),
        fork_slot,
        RelativeSyncCommittee::Current,
    );

    let sync_committee_messages = sync_messages
        .iter()
        .flat_map(|(messages, _)| messages.iter().map(|(message, _subnet)| message.clone()))
        .collect::<Vec<_>>();
    assert!(!sync_committee_messages.is_empty());

    client
        .post_beacon_pool_sync_committee_signatures(&sync_committee_messages)
        .await
        .unwrap();

    let signed_contributions = sync_messages
        .into_iter()
        .filter_map(|(_, op_aggregate)| op_aggregate)
        .collect::<Vec<_>>();
    assert!(!signed_contributions.is_empty());

    client
        .post_validator_contribution_and_proofs(&signed_contributions)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_committee_indices_across_fork() {
    let validator_count = E::sync_committee_size();
    let fork_epoch = Epoch::new(8);
    let spec = altair_spec(fork_epoch);
    let tester = InteractiveTester::<E>::new(Some(spec.clone()), validator_count).await;
    let harness = &tester.harness;
    let client = &tester.client;

    let all_validators = harness.get_all_validators();

    // Flatten subcommittees into a single vec.
    let flatten = |subcommittees: &[SyncSubcommittee]| -> Vec<u64> {
        subcommittees
            .iter()
            .flat_map(|sub| sub.indices.iter().copied())
            .collect()
    };

    // Prior to the fork the `sync_committees` endpoint should return a 400 error.
    assert_eq!(
        client
            .get_beacon_states_sync_committees(StateId::Slot(Slot::new(0)), None)
            .await
            .unwrap_err()
            .status()
            .unwrap(),
        400
    );
    assert_eq!(
        client
            .get_beacon_states_sync_committees(StateId::Head, Some(Epoch::new(0)))
            .await
            .unwrap_err()
            .status()
            .unwrap(),
        400
    );

    // If there's a skip slot at the fork slot, the endpoint will return a 400 until a block is
    // applied.
    let fork_slot = fork_epoch.start_slot(E::slots_per_epoch());
    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    let (_, state) = harness
        .add_attested_block_at_slot(
            fork_slot - 1,
            genesis_state,
            genesis_state_root,
            &all_validators,
        )
        .unwrap();

    harness.advance_slot();
    assert_eq!(harness.get_current_slot(), fork_slot);

    // Using the head state must fail.
    assert_eq!(
        client
            .get_beacon_states_sync_committees(StateId::Head, Some(fork_epoch))
            .await
            .unwrap_err()
            .status()
            .unwrap(),
        400
    );

    // In theory we could do a state advance and make this work, but to keep things simple I've
    // avoided doing that for now.
    assert_eq!(
        client
            .get_beacon_states_sync_committees(StateId::Slot(fork_slot), None)
            .await
            .unwrap_err()
            .status()
            .unwrap(),
        400
    );

    // Once the head is updated it should be useable for requests, including in the next sync
    // committee period.
    let state_root = state.canonical_root();
    harness
        .add_attested_block_at_slot(fork_slot + 1, state, state_root, &all_validators)
        .unwrap();

    let current_period = fork_epoch.sync_committee_period(&spec).unwrap();
    let next_period_epoch = spec.epochs_per_sync_committee_period * (current_period + 1);
    assert!(next_period_epoch > fork_epoch);

    for epoch in [
        None,
        Some(fork_epoch),
        Some(fork_epoch + 1),
        Some(next_period_epoch),
        Some(next_period_epoch + 1),
    ] {
        let committee = client
            .get_beacon_states_sync_committees(StateId::Head, epoch)
            .await
            .unwrap()
            .data;
        assert_eq!(committee.validators.len(), E::sync_committee_size());

        assert_eq!(
            committee.validators,
            flatten(&committee.validator_aggregates)
        );
    }
}
