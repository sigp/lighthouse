//! Tests for gossip verification of voluntary exits, propser slashings and attester slashings.

#![cfg(not(debug_assertions))]

use beacon_chain::{
    observed_operations::ObservationOutcome,
    test_utils::{
        test_spec, AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType,
    },
    BeaconChainError,
};
use lazy_static::lazy_static;
use sloggers::{null::NullLoggerBuilder, Build};
use state_processing::per_block_processing::errors::{
    AttesterSlashingInvalid, BlockOperationError, ExitInvalid, ProposerSlashingInvalid,
};
use std::sync::Arc;
use store::{LevelDB, StoreConfig};
use tempfile::{tempdir, TempDir};
use types::*;

pub const VALIDATOR_COUNT: usize = 24;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> =
        types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

type E = MinimalEthSpec;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;
type HotColdDB = store::HotColdDB<E, LevelDB<E>, LevelDB<E>>;

fn get_store(db_path: &TempDir) -> Arc<HotColdDB> {
    let spec = test_spec::<E>();
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    let blobs_path = db_path.path().join("blobs_db");
    let config = StoreConfig::default();
    let log = NullLoggerBuilder.build().expect("logger should build");
    HotColdDB::open(
        &hot_path,
        &cold_path,
        &blobs_path,
        |_, _, _| Ok(()),
        config,
        spec,
        log,
    )
    .expect("disk store should initialize")
}

fn get_harness(store: Arc<HotColdDB>, validator_count: usize) -> TestHarness {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();
    harness.advance_slot();
    harness
}

#[tokio::test]
async fn voluntary_exit() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);
    let spec = &harness.chain.spec.clone();

    harness
        .extend_chain(
            (E::slots_per_epoch() * (spec.shard_committee_period + 1)) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let validator_index1 = VALIDATOR_COUNT - 1;
    let validator_index2 = VALIDATOR_COUNT - 2;

    let exit1 = harness.make_voluntary_exit(
        validator_index1 as u64,
        Epoch::new(spec.shard_committee_period),
    );

    // First verification should show it to be fresh.
    assert!(matches!(
        harness
            .chain
            .verify_voluntary_exit_for_gossip(exit1.clone())
            .unwrap(),
        ObservationOutcome::New(_)
    ));

    // Second should not.
    assert!(matches!(
        harness
            .chain
            .verify_voluntary_exit_for_gossip(exit1.clone()),
        Ok(ObservationOutcome::AlreadyKnown)
    ));

    // A different exit for the same validator should also be detected as a duplicate.
    let exit2 = harness.make_voluntary_exit(
        validator_index1 as u64,
        Epoch::new(spec.shard_committee_period + 1),
    );
    assert!(matches!(
        harness.chain.verify_voluntary_exit_for_gossip(exit2),
        Ok(ObservationOutcome::AlreadyKnown)
    ));

    // Exit for a different validator should be fine.
    let exit3 = harness.make_voluntary_exit(
        validator_index2 as u64,
        Epoch::new(spec.shard_committee_period),
    );
    assert!(matches!(
        harness
            .chain
            .verify_voluntary_exit_for_gossip(exit3)
            .unwrap(),
        ObservationOutcome::New(_)
    ));
}

#[tokio::test]
async fn voluntary_exit_duplicate_in_state() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);
    let spec = &harness.chain.spec;

    harness
        .extend_chain(
            (E::slots_per_epoch() * (spec.shard_committee_period + 1)) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    harness.advance_slot();

    // Exit a validator.
    let exited_validator = 0;
    let exit =
        harness.make_voluntary_exit(exited_validator, Epoch::new(spec.shard_committee_period));
    let ObservationOutcome::New(verified_exit) = harness
        .chain
        .verify_voluntary_exit_for_gossip(exit.clone())
        .unwrap()
    else {
        panic!("exit should verify");
    };
    harness.chain.import_voluntary_exit(verified_exit);

    // Make a new block to include the exit.
    harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Verify validator is actually exited.
    assert_ne!(
        harness
            .get_current_state()
            .validators()
            .get(exited_validator as usize)
            .unwrap()
            .exit_epoch,
        spec.far_future_epoch
    );

    // Clear the in-memory gossip cache & try to verify the same exit on gossip.
    // It should still fail because gossip verification should check the validator's `exit_epoch`
    // field in the head state.
    harness
        .chain
        .observed_voluntary_exits
        .lock()
        .__reset_for_testing_only();

    assert!(matches!(
        harness
            .chain
            .verify_voluntary_exit_for_gossip(exit)
            .unwrap_err(),
        BeaconChainError::ExitValidationError(BlockOperationError::Invalid(
            ExitInvalid::AlreadyExited(index)
        )) if index == exited_validator
    ));
}

#[test]
fn proposer_slashing() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);

    let validator_index1 = VALIDATOR_COUNT - 1;
    let validator_index2 = VALIDATOR_COUNT - 2;

    let slashing1 = harness.make_proposer_slashing(validator_index1 as u64);

    // First slashing for this proposer should be allowed.
    assert!(matches!(
        harness
            .chain
            .verify_proposer_slashing_for_gossip(slashing1.clone())
            .unwrap(),
        ObservationOutcome::New(_)
    ));
    // Duplicate slashing should be detected.
    assert!(matches!(
        harness
            .chain
            .verify_proposer_slashing_for_gossip(slashing1.clone())
            .unwrap(),
        ObservationOutcome::AlreadyKnown
    ));

    // Different slashing for the same index should be rejected
    let slashing2 = ProposerSlashing {
        signed_header_1: slashing1.signed_header_2,
        signed_header_2: slashing1.signed_header_1,
    };
    assert!(matches!(
        harness
            .chain
            .verify_proposer_slashing_for_gossip(slashing2)
            .unwrap(),
        ObservationOutcome::AlreadyKnown
    ));

    // Proposer slashing for a different index should be accepted
    let slashing3 = harness.make_proposer_slashing(validator_index2 as u64);
    assert!(matches!(
        harness
            .chain
            .verify_proposer_slashing_for_gossip(slashing3)
            .unwrap(),
        ObservationOutcome::New(_)
    ));
}

#[tokio::test]
async fn proposer_slashing_duplicate_in_state() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);

    // Slash a validator.
    let slashed_validator = 0;
    let slashing = harness.make_proposer_slashing(slashed_validator);
    let ObservationOutcome::New(verified_slashing) = harness
        .chain
        .verify_proposer_slashing_for_gossip(slashing.clone())
        .unwrap()
    else {
        panic!("slashing should verify");
    };
    harness.chain.import_proposer_slashing(verified_slashing);

    // Make a new block to include the slashing.
    harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Verify validator is actually slashed.
    assert!(
        harness
            .get_current_state()
            .validators()
            .get(slashed_validator as usize)
            .unwrap()
            .slashed
    );

    // Clear the in-memory gossip cache & try to verify the same slashing on gossip.
    // It should still fail because gossip verification should check the validator's `slashed` field
    // in the head state.
    harness
        .chain
        .observed_proposer_slashings
        .lock()
        .__reset_for_testing_only();

    assert!(matches!(
        harness
            .chain
            .verify_proposer_slashing_for_gossip(slashing)
            .unwrap_err(),
        BeaconChainError::ProposerSlashingValidationError(BlockOperationError::Invalid(
            ProposerSlashingInvalid::ProposerNotSlashable(index)
        )) if index == slashed_validator
    ));
}

#[test]
fn attester_slashing() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);

    // First third of the validators
    let first_third = (0..VALIDATOR_COUNT as u64 / 3).collect::<Vec<_>>();
    // First half of the validators
    let first_half = (0..VALIDATOR_COUNT as u64 / 2).collect::<Vec<_>>();
    // Last third of the validators
    let last_third = (2 * VALIDATOR_COUNT as u64 / 3..VALIDATOR_COUNT as u64).collect::<Vec<_>>();
    // Last half of the validators
    let second_half = (VALIDATOR_COUNT as u64 / 2..VALIDATOR_COUNT as u64).collect::<Vec<_>>();

    // Slashing for first third of validators should be accepted.
    let slashing1 = harness.make_attester_slashing(first_third);
    assert!(matches!(
        harness
            .chain
            .verify_attester_slashing_for_gossip(slashing1.clone())
            .unwrap(),
        ObservationOutcome::New(_)
    ));

    // Overlapping slashing for first half of validators should also be accepted.
    let slashing2 = harness.make_attester_slashing(first_half);
    assert!(matches!(
        harness
            .chain
            .verify_attester_slashing_for_gossip(slashing2.clone())
            .unwrap(),
        ObservationOutcome::New(_)
    ));

    // Repeating slashing1 or slashing2 should be rejected
    assert!(matches!(
        harness
            .chain
            .verify_attester_slashing_for_gossip(slashing1.clone())
            .unwrap(),
        ObservationOutcome::AlreadyKnown
    ));
    assert!(matches!(
        harness
            .chain
            .verify_attester_slashing_for_gossip(slashing2.clone())
            .unwrap(),
        ObservationOutcome::AlreadyKnown
    ));

    // Slashing for last half of validators should be accepted (distinct from all existing)
    let slashing3 = harness.make_attester_slashing(second_half);
    assert!(matches!(
        harness
            .chain
            .verify_attester_slashing_for_gossip(slashing3)
            .unwrap(),
        ObservationOutcome::New(_)
    ));
    // Slashing for last third (contained in last half) should be rejected.
    let slashing4 = harness.make_attester_slashing(last_third);
    assert!(matches!(
        harness
            .chain
            .verify_attester_slashing_for_gossip(slashing4)
            .unwrap(),
        ObservationOutcome::AlreadyKnown
    ));
}

#[tokio::test]
async fn attester_slashing_duplicate_in_state() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);

    // Slash a validator.
    let slashed_validator = 0;
    let slashing = harness.make_attester_slashing(vec![slashed_validator]);
    let ObservationOutcome::New(verified_slashing) = harness
        .chain
        .verify_attester_slashing_for_gossip(slashing.clone())
        .unwrap()
    else {
        panic!("slashing should verify");
    };
    harness.chain.import_attester_slashing(verified_slashing);

    // Make a new block to include the slashing.
    harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Verify validator is actually slashed.
    assert!(
        harness
            .get_current_state()
            .validators()
            .get(slashed_validator as usize)
            .unwrap()
            .slashed
    );

    // Clear the in-memory gossip cache & try to verify the same slashing on gossip.
    // It should still fail because gossip verification should check the validator's `slashed` field
    // in the head state.
    harness
        .chain
        .observed_attester_slashings
        .lock()
        .__reset_for_testing_only();

    assert!(matches!(
        harness
            .chain
            .verify_attester_slashing_for_gossip(slashing)
            .unwrap_err(),
        BeaconChainError::AttesterSlashingValidationError(BlockOperationError::Invalid(
            AttesterSlashingInvalid::NoSlashableIndices
        ))
    ));
}
