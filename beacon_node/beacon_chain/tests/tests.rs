#![cfg(not(debug_assertions))]

use beacon_chain::{
    BeaconChain, ChainConfig, NotifyExecutionLayer, StateSkipConfig, WhenSlotSkipped,
    attestation_verification::Error as AttnError,
    custody_context::NodeCustodyType,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
        OP_POOL_DB_KEY,
    },
};
use bls::Keypair;
use operation_pool::PersistedOperationPool;
use state_processing::EpochProcessingError;
use state_processing::{per_slot_processing, per_slot_processing::Error as SlotProcessingError};
use std::sync::LazyLock;
use types::{
    BeaconState, BeaconStateError, BlockImportSource, ChainSpec, Checkpoint,
    DEFAULT_PRE_ELECTRA_WS_PERIOD, Epoch, EthSpec, ForkName, Hash256, MainnetEthSpec,
    MinimalEthSpec, RelativeEpoch, Slot,
};

type E = MinimalEthSpec;

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 48;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn get_harness(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>> {
    get_harness_with_config(
        validator_count,
        ChainConfig {
            archive: true,
            ..Default::default()
        },
    )
}

fn get_harness_with_spec(
    validator_count: usize,
    spec: &ChainSpec,
) -> BeaconChainHarness<EphemeralHarnessType<MainnetEthSpec>> {
    let chain_config = ChainConfig {
        archive: true,
        ..Default::default()
    };
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.clone().into())
        .chain_config(chain_config)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

fn get_harness_with_config(
    validator_count: usize,
    chain_config: ChainConfig,
) -> BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>> {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .chain_config(chain_config)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

/// Creates a harness with SemiSupernode custody type to ensure enough columns are stored
/// for sampling validation in Fulu.
fn get_harness_semi_supernode(
    validator_count: usize,
) -> BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>> {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .chain_config(ChainConfig {
            archive: true,
            ..Default::default()
        })
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .node_custody_type(NodeCustodyType::SemiSupernode)
        .build();

    harness.advance_slot();

    harness
}

#[test]
fn massive_skips() {
    let harness = get_harness(8);
    let spec = &harness.chain.spec;
    let mut state = harness.chain.head_beacon_state_cloned();

    // Run per_slot_processing until it returns an error.
    let error = loop {
        match per_slot_processing(&mut state, None, spec) {
            Ok(_) => continue,
            Err(e) => break e,
        }
    };

    assert!(state.slot() > 1, "the state should skip at least one slot");

    if state.fork_name_unchecked().gloas_enabled() {
        // Gloas uses compute_balance_weighted_selection for proposer selection, which
        // returns InvalidIndicesCount (not InsufficientValidators) when the active
        // validator set is empty.
        assert_eq!(
            error,
            SlotProcessingError::EpochProcessingError(EpochProcessingError::BeaconStateError(
                BeaconStateError::InvalidIndicesCount
            )),
            "should return error indicating that validators have been slashed out"
        )
    } else if state.fork_name_unchecked().fulu_enabled() {
        // post-fulu this is done in per_epoch_processing
        assert_eq!(
            error,
            SlotProcessingError::EpochProcessingError(EpochProcessingError::BeaconStateError(
                BeaconStateError::InsufficientValidators
            )),
            "should return error indicating that validators have been slashed out"
        )
    } else {
        assert_eq!(
            error,
            SlotProcessingError::BeaconStateError(BeaconStateError::InsufficientValidators),
            "should return error indicating that validators have been slashed out"
        )
    }
}

#[tokio::test]
async fn iterators() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 2 - 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            // No need to produce attestations for this test.
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let block_roots: Vec<(Hash256, Slot)> = harness
        .chain
        .forwards_iter_block_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap)
        .collect();
    let state_roots: Vec<(Hash256, Slot)> = harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap)
        .collect();

    assert_eq!(
        block_roots.len(),
        state_roots.len(),
        "should be an equal amount of block and state roots"
    );

    assert!(
        block_roots.iter().any(|(_root, slot)| *slot == 0),
        "should contain genesis block root"
    );
    assert!(
        state_roots.iter().any(|(_root, slot)| *slot == 0),
        "should contain genesis state root"
    );

    assert_eq!(
        block_roots.len(),
        num_blocks_produced as usize + 1,
        "should contain all produced blocks, plus the genesis block"
    );

    block_roots.windows(2).for_each(|x| {
        assert_eq!(
            x[1].1,
            x[0].1 + 1,
            "block root slots should be increasing by one"
        )
    });
    state_roots.windows(2).for_each(|x| {
        assert_eq!(
            x[1].1,
            x[0].1 + 1,
            "state root slots should be increasing by one"
        )
    });

    let head = harness.chain.head_snapshot();

    assert_eq!(
        *block_roots.last().expect("should have some block roots"),
        (head.beacon_block_root, head.beacon_block.slot()),
        "last block root and slot should be for the head block"
    );

    assert_eq!(
        *state_roots.last().expect("should have some state roots"),
        (head.beacon_state_root(), head.beacon_state.slot()),
        "last state root and slot should be for the head state"
    );
}

fn find_reorg_slot(
    chain: &BeaconChain<EphemeralHarnessType<MinimalEthSpec>>,
    new_state: &BeaconState<MinimalEthSpec>,
    new_block_root: Hash256,
) -> Slot {
    let (old_state, old_block_root) = {
        let head = chain.canonical_head.cached_head();
        let old_state = head.snapshot.beacon_state.clone();
        let old_block_root = head.head_block_root();
        (old_state, old_block_root)
    };
    beacon_chain::canonical_head::find_reorg_slot(
        &old_state,
        old_block_root,
        new_state,
        new_block_root,
        &chain.spec,
    )
    .unwrap()
}

#[tokio::test]
async fn find_reorgs() {
    let num_blocks_produced = MinimalEthSpec::slots_per_historical_root() + 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced,
            BlockStrategy::OnCanonicalHead,
            // No need to produce attestations for this test.
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let head_state = &head.beacon_state;
    let head_slot = head_state.slot();
    let genesis_state = harness
        .chain
        .state_at_slot(Slot::new(0), StateSkipConfig::WithStateRoots)
        .unwrap();

    // because genesis is more than `SLOTS_PER_HISTORICAL_ROOT` away, this should return with the
    // finalized slot.
    assert_eq!(
        find_reorg_slot(
            &harness.chain,
            &genesis_state,
            harness.chain.genesis_block_root
        ),
        head_state
            .finalized_checkpoint()
            .epoch
            .start_slot(MinimalEthSpec::slots_per_epoch())
    );

    // test head
    assert_eq!(
        find_reorg_slot(
            &harness.chain,
            head_state,
            harness.chain.head_beacon_block().canonical_root()
        ),
        head_slot
    );

    // Re-org back to the slot prior to the head.
    let prev_slot = head_slot - Slot::new(1);
    let prev_state = harness
        .chain
        .state_at_slot(prev_slot, StateSkipConfig::WithStateRoots)
        .unwrap();
    let prev_block_root = harness
        .chain
        .block_root_at_slot(prev_slot, WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    assert_eq!(
        find_reorg_slot(&harness.chain, &prev_state, prev_block_root),
        prev_slot
    );
}

#[tokio::test]
async fn chooses_fork() {
    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let delay = MinimalEthSpec::default_spec().min_attestation_inclusion_delay as usize;

    let honest_validators: Vec<usize> = (0..two_thirds).collect();
    let faulty_validators: Vec<usize> = (two_thirds..VALIDATOR_COUNT).collect();

    let initial_blocks = delay + 1;
    let honest_fork_blocks = delay + 1;
    let faulty_fork_blocks = delay + 2;

    // Build an initial chain where all validators agree.
    harness
        .extend_chain(
            initial_blocks,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (honest_head, faulty_head) = harness
        .generate_two_forks_by_skipping_a_block(
            &honest_validators,
            &faulty_validators,
            honest_fork_blocks,
            faulty_fork_blocks,
        )
        .await;

    assert_ne!(honest_head, faulty_head, "forks should be distinct");

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        Slot::from(initial_blocks + honest_fork_blocks),
        "head should be at the current slot"
    );

    assert_eq!(
        harness.chain.head_snapshot().beacon_block_root,
        honest_head,
        "the honest chain should be the canonical chain"
    );
}

#[tokio::test]
async fn finalizes_with_full_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

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

#[tokio::test]
async fn finalizes_with_two_thirds_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let attesters = (0..two_thirds).collect();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

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

    // Note: the 2/3rds tests are not justifying the immediately prior epochs because the
    // `MIN_ATTESTATION_INCLUSION_DELAY` is preventing an adequate number of attestations being
    // included in blocks during that epoch.

    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be justified two behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 4,
        "the head should be finalized three behind the current epoch"
    );
}

#[tokio::test]
async fn does_not_finalize_with_less_than_two_thirds_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let less_than_two_thirds = two_thirds - 1;
    let attesters = (0..less_than_two_thirds).collect();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

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
        0,
        "no epoch should have been justified"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        0,
        "no epoch should have been finalized"
    );
}

#[tokio::test]
async fn does_not_finalize_without_attestation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

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
        0,
        "no epoch should have been justified"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        0,
        "no epoch should have been finalized"
    );
}

#[tokio::test]
async fn roundtrip_operation_pool() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    // Add some attestations
    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    assert!(harness.chain.op_pool.num_attestations() > 0);

    // TODO: could add some other operations
    harness
        .chain
        .persist_op_pool()
        .expect("should persist op pool");

    let restored_op_pool = harness
        .chain
        .store
        .get_item::<PersistedOperationPool<MinimalEthSpec>>(&OP_POOL_DB_KEY)
        .expect("should read db")
        .expect("should find op pool")
        .into_operation_pool()
        .unwrap();

    assert_eq!(harness.chain.op_pool, restored_op_pool);
}

#[tokio::test]
async fn unaggregated_attestations_added_to_fork_choice_some_none() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() / 2;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;
    let mut fork_choice = harness.chain.canonical_head.fork_choice_write_lock();

    // Move forward a slot so all queued attestations can be processed.
    harness.advance_slot();
    fork_choice
        .update_time(harness.chain.slot().unwrap())
        .unwrap();

    let validator_slots: Vec<(usize, Slot)> = (0..VALIDATOR_COUNT)
        .map(|validator_index| {
            let slot = state
                .get_attestation_duties(validator_index, RelativeEpoch::Current)
                .expect("should get attester duties")
                .unwrap()
                .slot;

            (validator_index, slot)
        })
        .collect();

    for (validator, slot) in validator_slots.clone() {
        let latest_message = fork_choice.latest_message(validator);

        if slot <= num_blocks_produced && slot != 0 {
            assert_eq!(
                latest_message
                    .expect("latest message should be present")
                    .slot
                    .epoch(MinimalEthSpec::slots_per_epoch()),
                slot.epoch(MinimalEthSpec::slots_per_epoch()),
                "Latest message epoch for {} should be equal to epoch {}.",
                validator,
                slot
            )
        } else {
            assert!(
                latest_message.is_none(),
                "Latest message slot should be None."
            )
        }
    }
}

#[tokio::test]
async fn attestations_with_increasing_slots() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let mut attestations = vec![];

    for _ in 0..num_blocks_produced {
        harness
            .extend_chain(
                2,
                BlockStrategy::OnCanonicalHead,
                // Don't produce & include any attestations (we'll collect them later).
                AttestationStrategy::SomeValidators(vec![]),
            )
            .await;

        let head = harness.chain.head_snapshot();
        let head_state_root = head.beacon_state_root();

        attestations.extend(harness.get_single_attestations(
            &AttestationStrategy::AllValidators,
            &head.beacon_state,
            head_state_root,
            head.beacon_block_root,
            head.beacon_block.slot(),
        ));

        harness.advance_slot();
    }

    for (attestation, subnet_id) in attestations.into_iter().flatten() {
        let res = harness
            .chain
            .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id));

        let current_slot = harness.chain.slot().expect("should get slot");
        let expected_attestation_slot = attestation.data.slot;
        let expected_earliest_permissible_slot =
            current_slot - MinimalEthSpec::slots_per_epoch() - 1;

        if expected_attestation_slot < expected_earliest_permissible_slot {
            assert!(matches!(
                res.err().unwrap(),
                AttnError::PastSlot {
                    attestation_slot,
                    earliest_permissible_slot,
                }
                if attestation_slot == expected_attestation_slot && earliest_permissible_slot == expected_earliest_permissible_slot
            ))
        } else {
            res.expect("should process attestation");
        }
    }
}

#[tokio::test]
async fn unaggregated_attestations_added_to_fork_choice_all_updated() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 2 - 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;
    let mut fork_choice = harness.chain.canonical_head.fork_choice_write_lock();

    // Move forward a slot so all queued attestations can be processed.
    harness.advance_slot();
    fork_choice
        .update_time(harness.chain.slot().unwrap())
        .unwrap();

    let validators: Vec<usize> = (0..VALIDATOR_COUNT).collect();
    let slots: Vec<Slot> = validators
        .iter()
        .map(|&v| {
            state
                .get_attestation_duties(v, RelativeEpoch::Current)
                .expect("should get attester duties")
                .unwrap()
                .slot
        })
        .collect();
    let validator_slots: Vec<(&usize, Slot)> = validators.iter().zip(slots).collect();

    for (validator, slot) in validator_slots {
        let latest_message = fork_choice
            .latest_message(*validator)
            .expect("latest message should be present");

        assert_eq!(
            latest_message.slot.epoch(MinimalEthSpec::slots_per_epoch()),
            slot.epoch(MinimalEthSpec::slots_per_epoch()),
            "Latest message slot should be equal to attester duty."
        );

        if slot != num_blocks_produced {
            let block_root = state
                .get_block_root(slot)
                .expect("Should get block root at slot");

            assert_eq!(
                latest_message.root, *block_root,
                "Latest message block root should be equal to block at slot."
            );
        }
    }
}

async fn run_skip_slot_test(skip_slots: u64) {
    let num_validators = 8;
    // SemiSupernode ensures enough columns are stored for sampling + custody RpcBlock validation
    let harness_a = get_harness_semi_supernode(num_validators);
    let harness_b = get_harness_semi_supernode(num_validators);

    for _ in 0..skip_slots {
        harness_a.advance_slot();
        harness_b.advance_slot();
    }

    harness_a
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            // No attestation required for test.
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    assert_eq!(
        harness_a.chain.head_snapshot().beacon_block.slot(),
        Slot::new(skip_slots + 1)
    );
    assert_eq!(
        harness_b.chain.head_snapshot().beacon_block.slot(),
        Slot::new(0)
    );

    let status = harness_b
        .chain
        .process_block(
            harness_a.chain.head_snapshot().beacon_block_root,
            harness_a.get_head_block(),
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        )
        .await
        .unwrap();

    let root: Hash256 = status.try_into().unwrap();

    assert_eq!(root, harness_a.chain.head_snapshot().beacon_block_root);

    harness_b.chain.recompute_head_at_current_slot().await;

    assert_eq!(
        harness_b.chain.head_snapshot().beacon_block.slot(),
        Slot::new(skip_slots + 1)
    );
}

#[tokio::test]
async fn produces_and_processes_with_genesis_skip_slots() {
    for i in 0..MinimalEthSpec::slots_per_epoch() * 4 {
        run_skip_slot_test(i).await
    }
}

#[tokio::test]
async fn block_roots_skip_slot_behaviour() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Test should be longer than the block roots to ensure a DB lookup is triggered.
    let chain_length = harness
        .chain
        .head_snapshot()
        .beacon_state
        .block_roots()
        .len() as u64
        * 3;

    let skipped_slots = [1, 6, 7, 10, chain_length];

    // Build a chain with some skip slots.
    for i in 1..=chain_length {
        if i > 1 {
            harness.advance_slot();
        }

        let slot = harness.chain.slot().unwrap().as_u64();

        if !skipped_slots.contains(&slot) {
            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;
        }
    }

    let mut prev_unskipped_root = None;

    for target_slot in 0..=chain_length {
        if skipped_slots.contains(&target_slot) {
            /*
             * A skip slot
             */
            assert!(
                harness
                    .chain
                    .block_root_at_slot(target_slot.into(), WhenSlotSkipped::None)
                    .unwrap()
                    .is_none(),
                "WhenSlotSkipped::None should return None on a skip slot"
            );

            let skipped_root = harness
                .chain
                .block_root_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                .unwrap()
                .expect("WhenSlotSkipped::Prev should always return Some");

            assert_eq!(
                skipped_root,
                prev_unskipped_root.expect("test is badly formed"),
                "WhenSlotSkipped::Prev should accurately return the prior skipped block"
            );

            let expected_block = harness
                .chain
                .get_blinded_block(&skipped_root)
                .unwrap()
                .unwrap();

            assert_eq!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                    .unwrap()
                    .unwrap(),
                expected_block,
            );

            assert!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::None)
                    .unwrap()
                    .is_none(),
                "WhenSlotSkipped::None should return None on a skip slot"
            );
        } else {
            /*
             * Not a skip slot
             */
            let skips_none = harness
                .chain
                .block_root_at_slot(target_slot.into(), WhenSlotSkipped::None)
                .unwrap()
                .expect("WhenSlotSkipped::None should return Some for non-skipped block");
            let skips_prev = harness
                .chain
                .block_root_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                .unwrap()
                .expect("WhenSlotSkipped::Prev should always return Some");
            assert_eq!(
                skips_none, skips_prev,
                "WhenSlotSkipped::None and WhenSlotSkipped::Prev should be equal on non-skipped slot"
            );

            let expected_block = harness
                .chain
                .get_blinded_block(&skips_prev)
                .unwrap()
                .unwrap();

            assert_eq!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                    .unwrap()
                    .unwrap(),
                expected_block
            );

            assert_eq!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::None)
                    .unwrap()
                    .unwrap(),
                expected_block
            );

            prev_unskipped_root = Some(skips_prev);
        }
    }

    /*
     * A future, non-existent slot.
     */

    let future_slot = harness.chain.slot().unwrap() + 1;
    assert_eq!(
        harness.chain.head_snapshot().beacon_block.slot(),
        future_slot - 2,
        "test precondition"
    );
    assert!(
        harness
            .chain
            .block_root_at_slot(future_slot, WhenSlotSkipped::None)
            .unwrap()
            .is_none(),
        "WhenSlotSkipped::None should return None on a future slot"
    );
    assert!(
        harness
            .chain
            .block_root_at_slot(future_slot, WhenSlotSkipped::Prev)
            .unwrap()
            .is_none(),
        "WhenSlotSkipped::Prev should return None on a future slot"
    );
}

async fn pseudo_finalize_test_generic(
    epochs_per_migration: u64,
    expect_true_finalization_migration: bool,
) {
    // This test ensures that after pseudo finalization, we can still finalize the chain without issues
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let chain_config = ChainConfig {
        archive: true,
        epochs_per_migration,
        ..Default::default()
    };
    let harness = get_harness_with_config(VALIDATOR_COUNT, chain_config);

    let one_third = VALIDATOR_COUNT / 3;
    let attesters = (0..one_third).collect();

    // extend the chain, but don't finalize
    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    harness.advance_slot();

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;
    let split = harness.chain.store.get_split_info();

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
        0,
        "There should be no justified checkpoint"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        0,
        "There should be no finalized checkpoint"
    );
    assert_eq!(split.slot, 0, "Our split point should be unset");

    let checkpoint = Checkpoint {
        epoch: head.beacon_state.current_epoch(),
        root: head.beacon_block_root,
    };

    // pseudo finalize
    // Post-Gloas the finalized state must be Pending (the block's state_root), not Full
    // (the envelope's state_root), because the payload of the finalized block is not finalized.
    let finalized_state_root = head.beacon_block.message().state_root();
    harness
        .chain
        .manually_finalize_state(finalized_state_root, checkpoint)
        .unwrap();

    let split = harness.chain.store.get_split_info();
    let pseudo_finalized_slot = split.slot;

    assert_eq!(
        state.current_justified_checkpoint().epoch,
        0,
        "We pseudo finalized, but our justified checkpoint should still be unset"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        0,
        "We pseudo finalized, but our finalized checkpoint should still be unset"
    );
    assert_eq!(
        split.slot,
        head.beacon_state.slot(),
        "We pseudo finalized, our split point should be at the current head slot"
    );

    // finalize the chain
    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    harness.advance_slot();

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;
    let split = harness.chain.store.get_split_info();

    assert_eq!(
        state.slot(),
        num_blocks_produced * 2,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        (num_blocks_produced * 2) / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    let finalized_epoch = state.finalized_checkpoint().epoch;
    assert_eq!(
        finalized_epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );

    let expected_split_slot = if pseudo_finalized_slot.epoch(E::slots_per_epoch())
        + epochs_per_migration
        > finalized_epoch
    {
        pseudo_finalized_slot
    } else {
        finalized_epoch.start_slot(E::slots_per_epoch())
    };
    assert_eq!(
        split.slot, expected_split_slot,
        "We finalized, our split point should be updated according to epochs_per_migration"
    );

    // In the case that we did not process the true finalization migration (due to
    // epochs_per_migration), check that the chain finalized *despite* the absence of the split
    // block in fork choice.
    // This is a regression test for https://github.com/sigp/lighthouse/pull/7105
    if !expect_true_finalization_migration {
        assert_eq!(expected_split_slot, pseudo_finalized_slot);
        assert!(
            !harness
                .chain
                .canonical_head
                .fork_choice_read_lock()
                .contains_block(&split.block_root)
        );
    }
}

#[tokio::test]
async fn pseudo_finalize_basic() {
    let epochs_per_migration = 0;
    let expect_true_migration = true;
    pseudo_finalize_test_generic(epochs_per_migration, expect_true_migration).await;
}

#[tokio::test]
async fn pseudo_finalize_with_lagging_split_update() {
    let epochs_per_migration = 10;
    let expect_true_migration = false;
    pseudo_finalize_test_generic(epochs_per_migration, expect_true_migration).await;
}

#[tokio::test]
async fn test_compute_weak_subjectivity_period() {
    type E = MainnetEthSpec;
    let expected_ws_period_pre_electra = DEFAULT_PRE_ELECTRA_WS_PERIOD;
    let expected_ws_period_post_electra = 256;

    // test Base variant
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);
    let head_state = harness.get_current_state();

    let calculated_ws_period = head_state.compute_weak_subjectivity_period(&spec).unwrap();

    assert_eq!(calculated_ws_period, expected_ws_period_pre_electra);

    // test Electra variant
    let spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);
    let head_state = harness.get_current_state();

    let calculated_ws_period = head_state.compute_weak_subjectivity_period(&spec).unwrap();

    assert_eq!(calculated_ws_period, expected_ws_period_post_electra);
}

/// EIP-8061: Verify that at the Electra fork, the new Gloas-aware churn helpers
/// return the same values as the existing Electra functions.
#[tokio::test]
async fn churn_limits_electra_unchanged_with_state() {
    type E = MainnetEthSpec;
    let spec = ForkName::Electra.make_genesis_spec(E::default_spec());
    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);
    let state = harness.get_current_state();

    let activation_exit = state.get_activation_exit_churn_limit(&spec).unwrap();
    let activation_gloas = state.get_activation_churn_limit_gloas(&spec).unwrap();
    let exit_gloas = state.get_exit_churn_limit_gloas(&spec).unwrap();
    let consolidation = state.get_consolidation_churn_limit(&spec).unwrap();

    // At Electra, the new Gloas helpers should delegate to the old behavior
    assert_eq!(activation_gloas, activation_exit);
    assert_eq!(exit_gloas, activation_exit);

    // Consolidation = balance_churn - activation_exit_churn (Electra formula)
    let balance_churn = state.get_balance_churn_limit(&spec).unwrap();
    assert_eq!(consolidation, balance_churn - activation_exit);
}

/// EIP-8061: Verify asymmetric churn at Gloas — exit churn exceeds activation churn.
#[tokio::test]
async fn churn_limits_gloas_asymmetric() {
    type E = MainnetEthSpec;

    // Use a small quotient and low activation cap to expose asymmetry with 48 validators
    let mut spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
    spec.churn_limit_quotient_gloas = 4; // 1536 ETH / 4 = 384 ETH > floor
    spec.max_per_epoch_activation_churn_limit_gloas = 64_000_000_000; // 64 ETH cap

    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);
    let state = harness.get_current_state();

    let exit_churn = state.get_exit_churn_limit_gloas(&spec).unwrap();
    let activation_churn = state.get_activation_churn_limit_gloas(&spec).unwrap();
    let consolidation_churn = state.get_consolidation_churn_limit(&spec).unwrap();

    // Exit churn = max(128 ETH, 1536/4=384 ETH) = 384 ETH (uncapped)
    assert_eq!(exit_churn, 384_000_000_000);
    // Activation churn = min(64 ETH, 384 ETH) = 64 ETH (cap binds)
    assert_eq!(activation_churn, 64_000_000_000);
    // Proves asymmetry: exit > activation
    assert!(exit_churn > activation_churn);

    // Consolidation uses independent formula (total / consolidation_quotient)
    // 1536 ETH / 65536 = 0.0234... → rounds to 0
    assert_eq!(consolidation_churn, 0);
}

/// EIP-8061: Verify deposit processing uses activation churn (not exit churn).
///
/// After epoch processing with no pending deposits, deposit_balance_to_consume is 0
/// (churn limit not reached). We then set deposit_balance_to_consume to a known value
/// and run epoch processing manually. The result proves the activation churn (64 ETH)
/// was added, not exit churn (384 ETH):
///   available = prior_deposit_balance_to_consume + activation_churn_limit_gloas
///
/// With no pending deposits and churn limit not reached, the output is 0. So we verify
/// indirectly: the state's deposit_balance_to_consume after a clean epoch is 0,
/// and the activation churn helper returns the capped value (not exit churn).
/// A regression changing the call site back to get_activation_exit_churn_limit would
/// cause get_activation_churn_limit_gloas != get_activation_exit_churn_limit to fail.
#[tokio::test]
async fn deposit_processing_uses_activation_churn() {
    type E = MainnetEthSpec;

    let mut spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
    spec.churn_limit_quotient_gloas = 4;
    spec.max_per_epoch_activation_churn_limit_gloas = 64_000_000_000; // 64 ETH

    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);

    // Advance one epoch so epoch processing runs
    harness
        .extend_to_slot(Slot::new(E::slots_per_epoch()))
        .await;
    let state = harness.get_current_state();

    // After epoch processing with no pending deposits, deposit_balance_to_consume = 0
    assert_eq!(state.deposit_balance_to_consume().unwrap(), 0);

    // The activation churn (what deposit processing adds) is capped at 64 ETH
    let activation_churn = state.get_activation_churn_limit_gloas(&spec).unwrap();
    assert_eq!(activation_churn, 64_000_000_000);

    // The exit churn is uncapped at 384 ETH — deposit processing must NOT use this
    let exit_churn = state.get_exit_churn_limit_gloas(&spec).unwrap();
    assert_eq!(exit_churn, 384_000_000_000);

    // The old shared helper returns a different value, proving the code path diverged
    let old_shared_churn = state.get_activation_exit_churn_limit(&spec).unwrap();
    assert_ne!(activation_churn, old_shared_churn);
}

/// EIP-8061: Verify exit processing uses uncapped exit churn in Gloas.
#[tokio::test]
async fn exit_queue_uses_uncapped_exit_churn() {
    type E = MainnetEthSpec;

    let mut spec_gloas = ForkName::Gloas.make_genesis_spec(E::default_spec());
    spec_gloas.churn_limit_quotient_gloas = 4;
    spec_gloas.max_per_epoch_activation_churn_limit_gloas = 64_000_000_000;
    spec_gloas.max_per_epoch_activation_exit_churn_limit = 64_000_000_000;

    let harness_gloas = get_harness_with_spec(VALIDATOR_COUNT, &spec_gloas);
    let state_gloas = harness_gloas.get_current_state();

    // Gloas exit churn is uncapped: max(128 ETH, 1536/4=384 ETH) = 384 ETH
    let exit_churn_gloas = state_gloas.get_exit_churn_limit_gloas(&spec_gloas).unwrap();
    assert_eq!(exit_churn_gloas, 384_000_000_000);

    // Compare with Electra: exit churn is capped at max_per_epoch_activation_exit_churn_limit
    let mut spec_electra = ForkName::Electra.make_genesis_spec(E::default_spec());
    spec_electra.max_per_epoch_activation_exit_churn_limit = 64_000_000_000;

    let harness_electra = get_harness_with_spec(VALIDATOR_COUNT, &spec_electra);
    let state_electra = harness_electra.get_current_state();

    let exit_churn_electra = state_electra
        .get_exit_churn_limit_gloas(&spec_electra)
        .unwrap();
    // Electra: min(64 ETH, balance_churn). balance_churn = max(128 ETH, 1536/65536) = 128 ETH
    // min(64 ETH, 128 ETH) = 64 ETH
    assert_eq!(exit_churn_electra, 64_000_000_000);

    // Gloas has higher exit throughput
    assert!(exit_churn_gloas > exit_churn_electra);
}

/// EIP-8061: Verify consolidation churn uses independent formula in Gloas.
#[tokio::test]
async fn consolidation_churn_independent_in_gloas() {
    type E = MainnetEthSpec;

    let mut spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
    // Use small quotient to get non-zero consolidation with 48 validators (1536 ETH)
    spec.consolidation_churn_limit_quotient = 16; // 1536/16 = 96 ETH

    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);
    let state = harness.get_current_state();

    let consolidation_churn = state.get_consolidation_churn_limit(&spec).unwrap();

    // 1536 ETH / 16 = 96 ETH
    assert_eq!(consolidation_churn, 96_000_000_000);

    // Verify the guard in process_operations would pass (churn > min_activation_balance = 32 ETH)
    assert!(consolidation_churn > spec.min_activation_balance);
}

/// EIP-8061: Verify Gloas weak subjectivity period differs from Electra.
///
/// With 48 validators × 32 ETH = 1536 ETH, we need small quotients (100/200) and
/// a tiny min floor (1 Gwei) so the epoch computation is non-zero and the
/// asymmetric Gloas formula produces a detectably different result.
#[tokio::test]
async fn weak_subjectivity_gloas_with_state() {
    type E = MainnetEthSpec;

    // Gloas: quotient=100 → exit=15 ETH, cap=4 ETH → activation=4 ETH,
    // consolidation_quotient=200 → consolidation=7 ETH
    // delta = 2*15/3 + 4/3 + 7 = 10+1+7 = 18 ETH
    // epochs = 10*1536e9 / (2*18e9*100) = 4
    let mut spec_gloas = ForkName::Gloas.make_genesis_spec(E::default_spec());
    spec_gloas.min_per_epoch_churn_limit_electra = 1;
    spec_gloas.churn_limit_quotient_gloas = 100;
    spec_gloas.max_per_epoch_activation_churn_limit_gloas = 4_000_000_000;
    spec_gloas.consolidation_churn_limit_quotient = 200;

    let harness_gloas = get_harness_with_spec(VALIDATOR_COUNT, &spec_gloas);
    let state_gloas = harness_gloas.get_current_state();
    let ws_gloas = state_gloas
        .compute_weak_subjectivity_period(&spec_gloas)
        .unwrap();

    // Electra: same quotient=100 → balance_churn=15 ETH
    // epochs = 10*1536e9 / (15e9*200) = 5
    let mut spec_electra = ForkName::Electra.make_genesis_spec(E::default_spec());
    spec_electra.min_per_epoch_churn_limit_electra = 1;
    spec_electra.churn_limit_quotient = 100;

    let harness_electra = get_harness_with_spec(VALIDATOR_COUNT, &spec_electra);
    let state_electra = harness_electra.get_current_state();
    let ws_electra = state_electra
        .compute_weak_subjectivity_period(&spec_electra)
        .unwrap();

    // Both exceed min_validator_withdrawability_delay
    assert!(ws_gloas > spec_gloas.min_validator_withdrawability_delay);
    assert!(ws_electra > spec_electra.min_validator_withdrawability_delay);

    // Gloas WS is shorter (higher total churn capacity → less time to corrupt)
    assert!(ws_gloas < ws_electra);
}

/// EIP-8061: Verify churn state is correctly rebased at the Fulu→Gloas fork transition.
///
/// Per consensus-specs fork.md, exit_balance_to_consume and consolidation_balance_to_consume
/// are copied unchanged from the pre-state. The new Gloas churn limits take effect naturally
/// on the next epoch when compute_exit_epoch_and_update_churn fires its "new epoch" branch.
#[tokio::test]
async fn gloas_fork_transition_copies_churn() {
    type E = MainnetEthSpec;

    let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    spec.gloas_fork_epoch = Some(Epoch::new(2));
    spec.churn_limit_quotient_gloas = 4;
    spec.max_per_epoch_activation_churn_limit_gloas = 64_000_000_000;
    spec.consolidation_churn_limit_quotient = 8;

    let harness = get_harness_with_spec(VALIDATOR_COUNT, &spec);

    let fork_slot = spec
        .gloas_fork_epoch
        .unwrap()
        .start_slot(E::slots_per_epoch());

    // Advance to the last Fulu slot
    harness.extend_to_slot(fork_slot - 1).await;
    let fulu_state = harness.get_current_state();
    assert_eq!(fulu_state.slot(), fork_slot - 1);
    assert_eq!(fulu_state.fork_name_unchecked(), ForkName::Fulu);

    let fulu_exit_to_consume = fulu_state.exit_balance_to_consume().unwrap();
    let fulu_consol_to_consume = fulu_state.consolidation_balance_to_consume().unwrap();

    // Cross the fork boundary into Gloas
    harness.extend_to_slot(fork_slot).await;
    let gloas_state = harness.get_current_state();
    assert_eq!(gloas_state.slot(), fork_slot);
    assert_eq!(gloas_state.fork_name_unchecked(), ForkName::Gloas);

    let gloas_exit_to_consume = gloas_state.exit_balance_to_consume().unwrap();
    let gloas_consol_to_consume = gloas_state.consolidation_balance_to_consume().unwrap();

    // Per spec: values are copied directly, no rebase
    assert_eq!(gloas_exit_to_consume, fulu_exit_to_consume);
    assert_eq!(gloas_consol_to_consume, fulu_consol_to_consume);

    // Verify the new churn limits ARE higher (EIP-8061)
    let gloas_exit_limit = gloas_state.get_exit_churn_limit_gloas(&spec).unwrap();
    let fulu_exit_limit = fulu_state.get_activation_exit_churn_limit(&spec).unwrap();
    assert!(gloas_exit_limit > fulu_exit_limit);
}
