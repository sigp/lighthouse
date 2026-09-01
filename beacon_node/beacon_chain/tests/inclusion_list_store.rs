//! Tests for the inclusion list store reads on `BeaconChain`.
//!
//! These do not need a Heze state: the committee derives from the ordinary attester shuffling and
//! the store holds no fork-specific data.

use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{BeaconChainError, WhenSlotSkipped};
use bls::Signature;
use ssz_types::ProgressiveVariableList;
use types::{
    EthSpec, Hash256, InclusionList, MinimalEthSpec, RelativeEpoch, SignedInclusionList, Slot,
};

type E = MinimalEthSpec;

/// 8 validators per slot on minimal, fewer than the committee size, so positions repeat.
const VALIDATOR_COUNT: usize = 64;

fn get_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build()
}

fn transaction(byte: u8) -> ProgressiveVariableList<u8> {
    ProgressiveVariableList::new(vec![byte])
}

fn signed_inclusion_list(
    slot: Slot,
    validator_index: u64,
    dependent_root: Hash256,
    tx_byte: u8,
) -> SignedInclusionList {
    SignedInclusionList {
        message: InclusionList {
            slot,
            validator_index,
            dependent_root,
            transactions: ProgressiveVariableList::new(vec![transaction(tx_byte)]),
        },
        signature: Signature::empty(),
    }
}

#[tokio::test]
async fn committee_matches_the_state_level_helper() {
    let harness = get_harness();
    let slot = Slot::new(1);

    let block_root = harness.head_block_root();
    let (committee, dependent_root) = harness
        .chain
        .inclusion_list_committee(block_root, slot)
        .unwrap();

    assert_eq!(committee.len(), E::inclusion_list_committee_size());

    let mut state = harness.get_current_state();
    state
        .build_committee_cache(RelativeEpoch::Current, &harness.chain.spec)
        .unwrap();
    let expected = state.get_inclusion_list_committee(slot).unwrap();

    assert_eq!(committee, expected);

    // The store is keyed on the attester shuffling decision root, which is what a producer puts on
    // the inclusion list as its `dependent_root`.
    assert_eq!(
        dependent_root,
        state
            .attester_shuffling_decision_root(block_root, RelativeEpoch::Current)
            .unwrap()
    );
}

/// Anchoring on a block root from the slot's own epoch resolves, where the head root does not.
#[tokio::test]
async fn committee_resolves_for_a_slot_in_the_previous_epoch() {
    let harness = get_harness();
    harness
        .extend_slots(E::slots_per_epoch() as usize + 1)
        .await;

    let slot = Slot::new(E::slots_per_epoch() - 1);
    assert!(harness.chain.canonical_head.cached_head().head_slot() > slot);

    let block_root = harness
        .chain
        .block_root_at_slot(slot, WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();

    let (committee, _) = harness
        .chain
        .inclusion_list_committee(block_root, slot)
        .unwrap();

    let mut state = harness.get_current_state();
    state
        .build_committee_cache(RelativeEpoch::Previous, &harness.chain.spec)
        .unwrap();
    let expected = state.get_inclusion_list_committee(slot).unwrap();
    assert_eq!(committee, expected);

    assert!(matches!(
        harness
            .chain
            .inclusion_list_committee(harness.head_block_root(), slot),
        Err(BeaconChainError::InvalidShufflingId { .. })
    ));
}

#[tokio::test]
async fn bits_and_transactions_read_back_through_the_chain() {
    let harness = get_harness();
    let slot = Slot::new(1);
    let block_root = harness.head_block_root();

    let (committee, dependent_root) = harness
        .chain
        .inclusion_list_committee(block_root, slot)
        .unwrap();

    let timely_submitter = committee[0];
    let late_submitter = *committee
        .iter()
        .find(|index| **index != timely_submitter)
        .unwrap();

    let mut store = harness.chain.inclusion_list_store.write();
    store.process_inclusion_list(
        signed_inclusion_list(slot, timely_submitter, dependent_root, 0xaa),
        true,
    );
    store.process_inclusion_list(
        signed_inclusion_list(slot, late_submitter, dependent_root, 0xbb),
        false,
    );
    drop(store);

    // A validator holding two positions has both bits set.
    let bits = harness
        .chain
        .get_inclusion_list_bits(block_root, slot, false)
        .unwrap();
    for (position, validator_index) in committee.iter().enumerate() {
        let expected = *validator_index == timely_submitter || *validator_index == late_submitter;
        assert_eq!(bits.get(position).unwrap(), expected);
    }

    let timely_bits = harness
        .chain
        .get_inclusion_list_bits(block_root, slot, true)
        .unwrap();
    for (position, validator_index) in committee.iter().enumerate() {
        assert_eq!(
            timely_bits.get(position).unwrap(),
            *validator_index == timely_submitter
        );
    }

    assert!(
        harness
            .chain
            .is_inclusion_list_bits_inclusive(block_root, slot, &bits, false)
            .unwrap()
    );
    assert!(
        !harness
            .chain
            .is_inclusion_list_bits_inclusive(block_root, slot, &timely_bits, false)
            .unwrap()
    );

    // The spec does not require transaction order to be preserved.
    let transactions = harness
        .chain
        .get_inclusion_list_transactions(block_root, slot, false)
        .unwrap();
    assert_eq!(transactions.len(), 2);
    assert!(transactions.contains(&transaction(0xaa)));
    assert!(transactions.contains(&transaction(0xbb)));

    assert_eq!(
        harness
            .chain
            .get_inclusion_list_transactions(block_root, slot, true)
            .unwrap(),
        vec![transaction(0xaa)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_slot_task_prunes_the_store() {
    let harness = get_harness();
    let slot = Slot::new(1);
    let block_root = harness.head_block_root();

    let (committee, dependent_root) = harness
        .chain
        .inclusion_list_committee(block_root, slot)
        .unwrap();

    harness
        .chain
        .inclusion_list_store
        .write()
        .process_inclusion_list(
            signed_inclusion_list(slot, committee[0], dependent_root, 0xaa),
            true,
        );

    // The store retains the two slots behind the current one.
    while harness.chain.slot().unwrap() < slot + 2 {
        harness.advance_slot();
    }
    harness.chain.per_slot_task().await;
    assert!(
        !harness
            .chain
            .get_inclusion_list_transactions(block_root, slot, false)
            .unwrap()
            .is_empty()
    );

    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert!(
        harness
            .chain
            .get_inclusion_list_transactions(block_root, slot, false)
            .unwrap()
            .is_empty()
    );
}
