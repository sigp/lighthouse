//! Tests for the inclusion list store reads on `BeaconChain`.
//!
//! These do not need a Heze state: the committee derives from the ordinary attester shuffling and
//! the store holds no fork-specific data.

use beacon_chain::inclusion_list_store::InclusionListKey;
use beacon_chain::inclusion_list_verification::gossip_verified_inclusion_list::GossipVerifiedInclusionList;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{BeaconChainError, WhenSlotSkipped};
use bls::Signature;
use ssz_types::ProgressiveVariableList;
use state_processing::state_advance::complete_state_advance;
use types::{
    EthSpec, Hash256, InclusionList, ProgressiveTransactions, RelativeEpoch, SignedInclusionList,
    Slot, Spec,
};

type E = Spec;

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
    ProgressiveVariableList::new(vec![byte]).unwrap()
}

fn signed_inclusion_list(
    key: &InclusionListKey,
    validator_index: u64,
    tx_byte: u8,
) -> SignedInclusionList {
    SignedInclusionList {
        message: InclusionList {
            slot: key.slot(),
            validator_index,
            dependent_root: key.dependent_root(),
            transactions: ProgressiveVariableList::new(vec![transaction(tx_byte)]).unwrap(),
        },
        signature: Signature::empty(),
    }
}

#[tokio::test]
async fn committee_matches_the_state_level_helper() {
    let harness = get_harness();
    let block_root = harness.head_block_root();

    let key = harness
        .chain
        .inclusion_list_key_for_payload(block_root, Slot::new(2))
        .unwrap();
    assert_eq!(key.slot(), Slot::new(1));

    let committee = harness.chain.get_inclusion_list_committee(&key).unwrap();
    assert_eq!(committee.len(), E::inclusion_list_committee_size());

    let mut state = harness.get_current_state();
    state
        .build_committee_cache(RelativeEpoch::Current, &harness.chain.spec)
        .unwrap();
    assert_eq!(
        committee,
        state.get_inclusion_list_committee(key.slot()).unwrap()
    );

    // A producer puts the attester shuffling decision root on its inclusion list.
    assert_eq!(
        key.dependent_root(),
        state
            .attester_shuffling_decision_root(block_root, RelativeEpoch::Current)
            .unwrap()
    );
}

#[tokio::test]
async fn payload_at_slot_zero_has_no_key() {
    let harness = get_harness();

    assert!(matches!(
        harness
            .chain
            .inclusion_list_key_for_payload(harness.head_block_root(), Slot::new(0)),
        Err(BeaconChainError::ArithError(_))
    ));
}

/// Any later block on the same chain resolves the same key.
#[tokio::test]
async fn key_resolves_from_a_later_block() {
    let harness = get_harness();
    let slots_per_epoch = E::slots_per_epoch();
    harness.extend_slots(3 * slots_per_epoch as usize).await;

    let slot = Slot::new(2 * slots_per_epoch);
    let block_root = harness
        .chain
        .block_root_at_slot(slot, WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();

    let key = harness
        .chain
        .inclusion_list_key_for_payload(block_root, slot + 1)
        .unwrap();
    assert_eq!(
        harness
            .chain
            .inclusion_list_key_for_payload(harness.head_block_root(), slot + 1)
            .unwrap(),
        key
    );
    assert_eq!(
        Some(key.dependent_root()),
        harness
            .chain
            .block_root_at_slot(Slot::new(slots_per_epoch - 1), WhenSlotSkipped::Prev)
            .unwrap()
    );

    let mut state = harness.get_current_state();
    state
        .build_committee_cache(RelativeEpoch::Previous, &harness.chain.spec)
        .unwrap();
    assert_eq!(
        harness.chain.get_inclusion_list_committee(&key).unwrap(),
        state.get_inclusion_list_committee(slot).unwrap()
    );
}

/// Forks that split before the dependent slot get different keys, each with its own committee.
#[tokio::test]
async fn forks_get_their_own_key_and_committee() {
    let harness = get_harness();
    let slots_per_epoch = E::slots_per_epoch();
    let validators = (0..VALIDATOR_COUNT).collect::<Vec<_>>();
    harness.extend_slots(slots_per_epoch as usize - 2).await;
    let (fork_state, _) = harness.get_current_state_and_root();

    // Only the first fork has a block at the epoch 2 dependent slot.
    let payload_slot = Slot::new(2 * slots_per_epoch + 1);
    let mut keys = vec![];
    let mut committees = vec![];
    for slot in [slots_per_epoch - 1, slots_per_epoch] {
        let (_, _, head, mut state) = harness
            .add_attested_blocks_at_slots(fork_state.clone(), &[Slot::new(slot)], &validators)
            .await;

        let key = harness
            .chain
            .inclusion_list_key_for_payload(head.into(), payload_slot)
            .unwrap();
        complete_state_advance(&mut state, None, key.slot(), None, &harness.chain.spec).unwrap();
        state
            .build_committee_cache(RelativeEpoch::Current, &harness.chain.spec)
            .unwrap();
        let committee = harness.chain.get_inclusion_list_committee(&key).unwrap();
        assert_eq!(
            committee,
            state.get_inclusion_list_committee(key.slot()).unwrap()
        );
        keys.push(key);
        committees.push(committee);
    }
    assert_ne!(keys[0], keys[1]);
    assert_ne!(committees[0], committees[1]);
}

#[tokio::test]
async fn committee_rejects_a_wrong_dependent_root() {
    let harness = get_harness();
    harness
        .extend_slots(3 * E::slots_per_epoch() as usize)
        .await;

    let key = InclusionListKey::new(harness.head_slot(), harness.head_block_root());
    assert!(matches!(
        harness.chain.get_inclusion_list_committee(&key),
        Err(BeaconChainError::InclusionListDependentRootMismatch { .. })
    ));
}

/// A payload at the first slot of an epoch reads the lists of the previous epoch's last slot.
#[tokio::test]
async fn key_at_an_epoch_boundary() {
    let harness = get_harness();
    let slots_per_epoch = E::slots_per_epoch();
    harness.extend_slots(3 * slots_per_epoch as usize).await;

    let payload_slot = Slot::new(3 * slots_per_epoch);
    let parent_root = harness
        .chain
        .block_root_at_slot(payload_slot - 1, WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();
    let key = harness
        .chain
        .inclusion_list_key_for_payload(parent_root, payload_slot)
        .unwrap();

    assert_eq!(key.slot(), payload_slot - 1);
    assert_eq!(
        harness
            .chain
            .inclusion_list_key(parent_root, payload_slot - 1)
            .unwrap(),
        key
    );
    // The epoch 2 shuffling is decided by the last block of epoch 0.
    assert_eq!(
        Some(key.dependent_root()),
        harness
            .chain
            .block_root_at_slot(Slot::new(slots_per_epoch - 1), WhenSlotSkipped::Prev)
            .unwrap()
    );
}

/// A parent several epochs behind the payload still resolves the key and its committee.
#[tokio::test]
async fn key_after_skipped_epochs() {
    let harness = get_harness();
    let genesis_root = harness.head_block_root();
    let payload_slot = Slot::new(3 * E::slots_per_epoch() + 1);
    while harness.chain.slot().unwrap() < payload_slot {
        harness.advance_slot();
    }

    let key = harness
        .chain
        .inclusion_list_key_for_payload(genesis_root, payload_slot)
        .unwrap();
    assert_eq!(key.dependent_root(), genesis_root);

    let mut state = harness.get_current_state();
    complete_state_advance(&mut state, None, key.slot(), None, &harness.chain.spec).unwrap();
    state
        .build_committee_cache(RelativeEpoch::Current, &harness.chain.spec)
        .unwrap();
    assert_eq!(
        harness.chain.get_inclusion_list_committee(&key).unwrap(),
        state.get_inclusion_list_committee(key.slot()).unwrap()
    );
}

#[tokio::test]
async fn bits_and_transactions_read_back_through_the_store() {
    let harness = get_harness();
    let key = harness
        .chain
        .inclusion_list_key_for_payload(harness.head_block_root(), Slot::new(2))
        .unwrap();
    let committee = harness.chain.get_inclusion_list_committee(&key).unwrap();

    let timely_submitter = committee[0];
    let late_submitter = *committee
        .iter()
        .find(|index| **index != timely_submitter)
        .unwrap();

    let mut store = harness.chain.inclusion_list_store.write();
    store.process_inclusion_list(GossipVerifiedInclusionList {
        signed_inclusion_list: signed_inclusion_list(&key, timely_submitter, 0xaa),
        is_timely: true,
    });
    store.process_inclusion_list(GossipVerifiedInclusionList {
        signed_inclusion_list: signed_inclusion_list(&key, late_submitter, 0xbb),
        is_timely: false,
    });

    // A validator holding two positions has both bits set.
    let bits = store
        .get_inclusion_list_bits(&committee, &key, false)
        .unwrap();
    for (position, validator_index) in committee.iter().enumerate() {
        let expected = *validator_index == timely_submitter || *validator_index == late_submitter;
        assert_eq!(bits.get(position).unwrap(), expected);
    }

    let timely_bits = store
        .get_inclusion_list_bits(&committee, &key, true)
        .unwrap();
    for (position, validator_index) in committee.iter().enumerate() {
        assert_eq!(
            timely_bits.get(position).unwrap(),
            *validator_index == timely_submitter
        );
    }

    assert!(
        store
            .is_inclusion_list_bits_inclusive(&committee, &key, &bits, false)
            .unwrap()
    );
    assert!(
        !store
            .is_inclusion_list_bits_inclusive(&committee, &key, &timely_bits, false)
            .unwrap()
    );
    assert!(
        store
            .is_inclusion_list_bits_inclusive(&committee, &key, &timely_bits, true)
            .unwrap()
    );

    // The spec does not require transaction order to be preserved.
    let transactions = store.get_inclusion_list_transactions(&key, false);
    assert_eq!(transactions.len(), 2);
    assert!(transactions.contains(&transaction(0xaa)));
    assert!(transactions.contains(&transaction(0xbb)));

    assert_eq!(
        store.get_inclusion_list_transactions(&key, true),
        vec![transaction(0xaa)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_slot_task_prunes_the_store() {
    let harness = get_harness();
    let key = harness
        .chain
        .inclusion_list_key_for_payload(harness.head_block_root(), Slot::new(2))
        .unwrap();
    let committee = harness.chain.get_inclusion_list_committee(&key).unwrap();

    harness
        .chain
        .inclusion_list_store
        .write()
        .process_inclusion_list(GossipVerifiedInclusionList {
            signed_inclusion_list: signed_inclusion_list(&key, committee[0], 0xaa),
            is_timely: true,
        });

    // The store retains the two slots behind the current one.
    while harness.chain.slot().unwrap() < key.slot() + 2 {
        harness.advance_slot();
    }
    harness.chain.per_slot_task().await;
    assert!(
        !harness
            .chain
            .inclusion_list_store
            .read()
            .get_inclusion_list_transactions(&key, false)
            .is_empty()
    );

    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert!(
        harness
            .chain
            .inclusion_list_store
            .read()
            .get_inclusion_list_transactions(&key, false)
            .is_empty()
    );
}

#[tokio::test]
async fn proposer_inclusion_list_transactions_returns_the_stored_inclusion_list() {
    let harness = get_harness();
    let slot = Slot::new(1);
    let block_root = harness.head_block_root();

    let key = harness.chain.inclusion_list_key(block_root, slot).unwrap();
    let committee = harness.chain.get_inclusion_list_committee(&key).unwrap();

    harness
        .chain
        .inclusion_list_store
        .write()
        .process_inclusion_list(GossipVerifiedInclusionList {
            signed_inclusion_list: signed_inclusion_list(&key, committee[0], 0xaa),
            is_timely: true,
        });

    assert_eq!(
        harness
            .chain
            .proposer_inclusion_list_transactions(block_root, slot),
        ProgressiveTransactions::new(vec![transaction(0xaa)]).unwrap()
    );
}

#[tokio::test]
async fn proposer_inclusion_list_transactions_includes_untimely_lists() {
    let harness = get_harness();
    let slot = Slot::new(1);
    let block_root = harness.head_block_root();

    let key = harness.chain.inclusion_list_key(block_root, slot).unwrap();
    let committee = harness.chain.get_inclusion_list_committee(&key).unwrap();

    let timely_submitter = committee[0];
    let late_submitter = *committee
        .iter()
        .find(|index| **index != timely_submitter)
        .unwrap();

    let mut store = harness.chain.inclusion_list_store.write();
    store.process_inclusion_list(GossipVerifiedInclusionList {
        signed_inclusion_list: signed_inclusion_list(&key, timely_submitter, 0xaa),
        is_timely: true,
    });
    store.process_inclusion_list(GossipVerifiedInclusionList {
        signed_inclusion_list: signed_inclusion_list(&key, late_submitter, 0xbb),
        is_timely: false,
    });
    drop(store);

    let transactions = harness
        .chain
        .proposer_inclusion_list_transactions(block_root, slot);
    assert_eq!(transactions.len(), 2);
    assert!(transactions.contains(&transaction(0xaa)));
    assert!(transactions.contains(&transaction(0xbb)));
}

#[tokio::test]
async fn proposer_inclusion_list_transactions_is_empty_when_the_key_cannot_be_resolved() {
    let harness = get_harness();
    let slot = Slot::new(1);
    let unknown_root = Hash256::ZERO;

    assert!(
        harness
            .chain
            .inclusion_list_key(unknown_root, slot)
            .is_err()
    );

    assert_eq!(
        harness
            .chain
            .proposer_inclusion_list_transactions(unknown_root, slot),
        ProgressiveTransactions::empty()
    );
}
