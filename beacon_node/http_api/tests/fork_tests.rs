//! Tests for API behaviour across fork boundaries.
use crate::common::*;
use beacon_chain::{
    test_utils::{RelativeSyncCommittee, DEFAULT_ETH1_BLOCK_HASH, HARNESS_GENESIS_TIME},
    StateSkipConfig,
};
use eth2::types::{IndexedErrorMessage, StateId, SyncSubcommittee};
use genesis::{bls_withdrawal_credentials, interop_genesis_state_with_withdrawal_credentials};
use std::collections::HashSet;
use types::{
    test_utils::{generate_deterministic_keypair, generate_deterministic_keypairs},
    Address, ChainSpec, Epoch, EthSpec, Hash256, MinimalEthSpec, Slot,
};

type E = MinimalEthSpec;

fn altair_spec(altair_fork_epoch: Epoch) -> ChainSpec {
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec
}

fn capella_spec(capella_fork_epoch: Epoch) -> ChainSpec {
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));
    spec.bellatrix_fork_epoch = Some(Epoch::new(0));
    spec.capella_fork_epoch = Some(capella_fork_epoch);
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
        .await
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
        .await
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
        .await
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
        .await
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

/// Assert that an HTTP API error has the given status code and indexed errors for the given indices.
fn assert_server_indexed_error(error: eth2::Error, status_code: u16, indices: Vec<usize>) {
    let eth2::Error::ServerIndexedMessage(IndexedErrorMessage {
        code,
        failures,
        ..
    }) = error else {
        panic!("wrong error, expected ServerIndexedMessage, got: {error:?}")
    };
    assert_eq!(code, status_code);
    assert_eq!(failures.len(), indices.len());
    for (index, failure) in indices.into_iter().zip(failures) {
        assert_eq!(failure.index, index as u64);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bls_to_execution_changes_update_all_around_capella_fork() {
    let validator_count = 128;
    let fork_epoch = Epoch::new(2);
    let spec = capella_spec(fork_epoch);
    let max_bls_to_execution_changes = E::max_bls_to_execution_changes();

    // Use a genesis state with entirely BLS withdrawal credentials.
    // Offset keypairs by `validator_count` to create keys distinct from the signing keys.
    let validator_keypairs = generate_deterministic_keypairs(validator_count);
    let withdrawal_keypairs = (0..validator_count)
        .map(|i| Some(generate_deterministic_keypair(i + validator_count)))
        .collect::<Vec<_>>();
    let withdrawal_credentials = withdrawal_keypairs
        .iter()
        .map(|keypair| bls_withdrawal_credentials(&keypair.as_ref().unwrap().pk, &spec))
        .collect::<Vec<_>>();
    let genesis_state = interop_genesis_state_with_withdrawal_credentials(
        &validator_keypairs,
        &withdrawal_credentials,
        HARNESS_GENESIS_TIME,
        Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
        None,
        &spec,
    )
    .unwrap();

    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(spec.clone()),
        validator_count,
        Some(Box::new(|harness_builder| {
            harness_builder
                .keypairs(validator_keypairs)
                .withdrawal_keypairs(withdrawal_keypairs)
                .genesis_state_ephemeral_store(genesis_state)
        })),
        None,
    )
    .await;
    let harness = &tester.harness;
    let client = &tester.client;

    let all_validators = harness.get_all_validators();
    let all_validators_u64 = all_validators.iter().map(|x| *x as u64).collect::<Vec<_>>();

    // Create a bunch of valid address changes.
    let valid_address_changes = all_validators_u64
        .iter()
        .map(|&validator_index| {
            harness.make_bls_to_execution_change(
                validator_index,
                Address::from_low_u64_be(validator_index),
            )
        })
        .collect::<Vec<_>>();

    // Address changes which conflict with `valid_address_changes` on the address chosen.
    let conflicting_address_changes = all_validators_u64
        .iter()
        .map(|&validator_index| {
            harness.make_bls_to_execution_change(
                validator_index,
                Address::from_low_u64_be(validator_index + 1),
            )
        })
        .collect::<Vec<_>>();

    // Address changes signed with the wrong key.
    let wrong_key_address_changes = all_validators_u64
        .iter()
        .map(|&validator_index| {
            // Use the correct pubkey.
            let pubkey = &harness.get_withdrawal_keypair(validator_index).pk;
            // And the wrong secret key.
            let secret_key = &harness
                .get_withdrawal_keypair((validator_index + 1) % validator_count as u64)
                .sk;
            harness.make_bls_to_execution_change_with_keys(
                validator_index,
                Address::from_low_u64_be(validator_index),
                pubkey,
                secret_key,
            )
        })
        .collect::<Vec<_>>();

    // Submit some changes before Capella. Just enough to fill two blocks.
    let num_pre_capella = validator_count / 4;
    let blocks_filled_pre_capella = 2;
    assert_eq!(
        num_pre_capella,
        blocks_filled_pre_capella * max_bls_to_execution_changes
    );

    client
        .post_beacon_pool_bls_to_execution_changes(&valid_address_changes[..num_pre_capella])
        .await
        .unwrap();

    let expected_received_pre_capella_messages = valid_address_changes[..num_pre_capella].to_vec();

    // Conflicting changes for the same validators should all fail.
    let error = client
        .post_beacon_pool_bls_to_execution_changes(&conflicting_address_changes[..num_pre_capella])
        .await
        .unwrap_err();
    assert_server_indexed_error(error, 400, (0..num_pre_capella).collect());

    // Re-submitting the same changes should be accepted.
    client
        .post_beacon_pool_bls_to_execution_changes(&valid_address_changes[..num_pre_capella])
        .await
        .unwrap();

    // Invalid changes signed with the wrong keys should all be rejected without affecting the seen
    // indices filters (apply ALL of them).
    let error = client
        .post_beacon_pool_bls_to_execution_changes(&wrong_key_address_changes)
        .await
        .unwrap_err();
    assert_server_indexed_error(error, 400, all_validators.clone());

    // Advance to right before Capella.
    let capella_slot = fork_epoch.start_slot(E::slots_per_epoch());
    harness.extend_to_slot(capella_slot - 1).await;
    assert_eq!(harness.head_slot(), capella_slot - 1);

    assert_eq!(
        harness
            .chain
            .op_pool
            .get_bls_to_execution_changes_received_pre_capella(
                &harness.chain.head_snapshot().beacon_state,
                &spec,
            )
            .into_iter()
            .collect::<HashSet<_>>(),
        HashSet::from_iter(expected_received_pre_capella_messages.into_iter()),
        "all pre-capella messages should be queued for capella broadcast"
    );

    // Add Capella blocks which should be full of BLS to execution changes.
    for i in 0..validator_count / max_bls_to_execution_changes {
        let head_block_root = harness.extend_slots(1).await;
        let head_block = harness
            .chain
            .get_block(&head_block_root)
            .await
            .unwrap()
            .unwrap();

        let bls_to_execution_changes = head_block
            .message()
            .body()
            .bls_to_execution_changes()
            .unwrap();

        // Block should be full.
        assert_eq!(
            bls_to_execution_changes.len(),
            max_bls_to_execution_changes,
            "block not full on iteration {i}"
        );

        // Included changes should be the ones from `valid_address_changes` in any order.
        for address_change in bls_to_execution_changes.iter() {
            assert!(valid_address_changes.contains(address_change));
        }

        // After the initial 2 blocks, add the rest of the changes using a large
        // request containing all the valid, all the conflicting and all the invalid.
        // Despite the invalid and duplicate messages, the new ones should still get picked up by
        // the pool.
        if i == blocks_filled_pre_capella - 1 {
            let all_address_changes: Vec<_> = [
                valid_address_changes.clone(),
                conflicting_address_changes.clone(),
                wrong_key_address_changes.clone(),
            ]
            .concat();

            let error = client
                .post_beacon_pool_bls_to_execution_changes(&all_address_changes)
                .await
                .unwrap_err();
            assert_server_indexed_error(
                error,
                400,
                (validator_count..3 * validator_count).collect(),
            );
        }
    }

    // Eventually all validators should have eth1 withdrawal credentials.
    let head_state = harness.get_current_state();
    for validator in head_state.validators() {
        assert!(validator.has_eth1_withdrawal_credential(&spec));
    }
}
