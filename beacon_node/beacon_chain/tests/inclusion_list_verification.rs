//! Tests for the gossip verification of inclusion lists.
use beacon_chain::WhenSlotSkipped;
use beacon_chain::inclusion_list_store::InsertOutcome;
use beacon_chain::inclusion_list_verification::InclusionListVerificationError;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use slot_clock::SlotClock;
use ssz_types::ProgressiveVariableList;
use std::time::Duration;
use types::{
    Domain, EthSpec, Hash256, InclusionList, MinimalEthSpec, ProgressiveTransactions,
    SignedInclusionList, SignedRoot, Slot,
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

fn transactions(txs: Vec<Vec<u8>>) -> ProgressiveTransactions {
    ProgressiveVariableList::new(
        txs.into_iter()
            .map(|tx| ProgressiveVariableList::new(tx).unwrap())
            .collect(),
    )
    .unwrap()
}

fn sign(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    message: InclusionList,
    signer: usize,
) -> SignedInclusionList {
    let spec = &harness.spec;
    let epoch = message.slot.epoch(E::slots_per_epoch());
    let domain = spec.get_domain(
        epoch,
        Domain::InclusionListCommittee,
        &spec.fork_at_epoch(epoch),
        harness.chain.genesis_validators_root,
    );
    let signature = harness.validator_keypairs[signer]
        .sk
        .sign(message.signing_root(domain));
    SignedInclusionList { message, signature }
}

fn committee_member(harness: &BeaconChainHarness<EphemeralHarnessType<E>>, slot: Slot) -> u64 {
    let (committee, _) = harness
        .chain
        .inclusion_list_committee(harness.head_block_root(), slot)
        .unwrap();
    committee[0]
}

fn inclusion_list(
    slot: Slot,
    validator_index: u64,
    dependent_root: Hash256,
    txs: Vec<Vec<u8>>,
) -> InclusionList {
    InclusionList {
        slot,
        validator_index,
        dependent_root,
        transactions: transactions(txs),
    }
}

/// A harness at slot 1 with no blocks, so the genesis block is the dependent block.
fn genesis_harness() -> (BeaconChainHarness<EphemeralHarnessType<E>>, Slot, Hash256) {
    let harness = get_harness();
    harness.advance_slot();
    let slot = harness.chain.slot().unwrap();
    let dependent_root = harness.head_block_root();
    (harness, slot, dependent_root)
}

fn valid_inclusion_list(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    slot: Slot,
    dependent_root: Hash256,
    tx_byte: u8,
) -> SignedInclusionList {
    let validator_index = committee_member(harness, slot);
    sign(
        harness,
        inclusion_list(slot, validator_index, dependent_root, vec![vec![tx_byte]]),
        validator_index as usize,
    )
}

#[tokio::test]
async fn valid_inclusion_list_is_accepted_and_imported() {
    let (harness, slot, dependent_root) = genesis_harness();
    let signed = valid_inclusion_list(&harness, slot, dependent_root, 0xaa);

    let verified = harness
        .chain
        .verify_inclusion_list_for_gossip(signed)
        .expect("should verify");
    assert!(verified.is_timely);
    assert_eq!(
        harness.chain.import_inclusion_list(verified),
        InsertOutcome::New
    );
}

#[tokio::test]
async fn inclusion_list_after_the_deadline_is_not_timely() {
    let (harness, slot, dependent_root) = genesis_harness();
    let deadline =
        harness.chain.slot_clock.start_of(slot).unwrap() + harness.spec.get_inclusion_list_due();
    harness.chain.slot_clock.set_current_time(deadline);

    let signed = valid_inclusion_list(&harness, slot, dependent_root, 0xaa);
    let verified = harness
        .chain
        .verify_inclusion_list_for_gossip(signed)
        .expect("should verify");
    assert!(!verified.is_timely);
}

#[tokio::test]
async fn third_inclusion_list_from_a_validator_is_ignored() {
    let (harness, slot, dependent_root) = genesis_harness();

    // An equivocating second list still counts as a valid message.
    for tx_byte in [0xaa, 0xbb] {
        let signed = valid_inclusion_list(&harness, slot, dependent_root, tx_byte);
        let verified = harness
            .chain
            .verify_inclusion_list_for_gossip(signed)
            .expect("should verify");
        harness.chain.import_inclusion_list(verified);
    }

    let signed = valid_inclusion_list(&harness, slot, dependent_root, 0xcc);
    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(signed),
        Err(InclusionListVerificationError::AlreadySeenTwice { .. })
    ));
}

#[tokio::test]
async fn inclusion_list_outside_the_current_slot_is_ignored() {
    let (harness, slot, dependent_root) = genesis_harness();

    let future = valid_inclusion_list(&harness, slot + 1, dependent_root, 0xaa);
    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(future),
        Err(InclusionListVerificationError::FutureSlot { .. })
    ));

    // Move past the clock disparity allowance so the previous slot is out of range.
    harness.chain.slot_clock.set_current_time(
        harness.chain.slot_clock.start_of(slot).unwrap() + Duration::from_secs(1),
    );
    let past = valid_inclusion_list(&harness, slot - 1, dependent_root, 0xaa);
    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(past),
        Err(InclusionListVerificationError::PastSlot { .. })
    ));
}

#[tokio::test]
async fn inclusion_list_with_no_transaction_bytes_is_ignored() {
    let (harness, slot, dependent_root) = genesis_harness();
    let validator_index = committee_member(&harness, slot);

    // Empty transactions still add up to zero bytes, so this is an ignore, not a reject.
    for txs in [vec![], vec![vec![]]] {
        let signed = sign(
            &harness,
            inclusion_list(slot, validator_index, dependent_root, txs),
            validator_index as usize,
        );
        assert!(matches!(
            harness.chain.verify_inclusion_list_for_gossip(signed),
            Err(InclusionListVerificationError::EmptyTransactions)
        ));
    }
}

#[tokio::test]
async fn inclusion_list_with_invalid_transactions_is_rejected() {
    let (harness, slot, dependent_root) = genesis_harness();
    let validator_index = committee_member(&harness, slot);
    let too_large = harness.spec.max_transactions_bytes_per_inclusion_list as usize + 1;

    for txs in [vec![vec![0xaa; too_large]], vec![vec![0xaa], vec![]]] {
        let signed = sign(
            &harness,
            inclusion_list(slot, validator_index, dependent_root, txs),
            validator_index as usize,
        );
        assert!(matches!(
            harness.chain.verify_inclusion_list_for_gossip(signed),
            Err(InclusionListVerificationError::InvalidTransactions(_))
        ));
    }
}

#[tokio::test]
async fn inclusion_list_with_unknown_dependent_root_is_ignored() {
    let (harness, slot, _) = genesis_harness();
    let signed = valid_inclusion_list(&harness, slot, Hash256::repeat_byte(0xff), 0xaa);

    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(signed),
        Err(InclusionListVerificationError::DependentRootUnknown { .. })
    ));
}

#[tokio::test]
async fn inclusion_list_from_a_non_member_is_rejected() {
    let (harness, slot, dependent_root) = genesis_harness();
    let (committee, _) = harness
        .chain
        .inclusion_list_committee(dependent_root, slot)
        .unwrap();
    let non_member = (0..VALIDATOR_COUNT as u64)
        .find(|index| !committee.contains(index))
        .unwrap();

    let signed = sign(
        &harness,
        inclusion_list(slot, non_member, dependent_root, vec![vec![0xaa]]),
        non_member as usize,
    );
    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(signed),
        Err(InclusionListVerificationError::NotInCommittee { .. })
    ));
}

#[tokio::test]
async fn inclusion_list_with_invalid_signature_is_rejected() {
    let (harness, slot, dependent_root) = genesis_harness();
    let validator_index = committee_member(&harness, slot);
    let other_signer = (validator_index as usize + 1) % VALIDATOR_COUNT;

    let signed = sign(
        &harness,
        inclusion_list(slot, validator_index, dependent_root, vec![vec![0xaa]]),
        other_signer,
    );
    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(signed),
        Err(InclusionListVerificationError::InvalidSignature)
    ));
}

/// For a slot in epoch 2, the dependent block is the last block of epoch 0.
#[tokio::test]
async fn dependent_root_must_be_the_shuffling_decision_block() {
    let harness = get_harness();
    let slot = E::slots_per_epoch() * 2;
    harness.extend_to_slot(Slot::new(slot)).await;
    let slot = Slot::new(slot);
    let dependent_slot = Slot::new(E::slots_per_epoch() - 1);
    let block_root_at = |slot: Slot| {
        harness
            .chain
            .block_root_at_slot(slot, WhenSlotSkipped::None)
            .unwrap()
            .unwrap()
    };

    let (_, head_dependent_root) = harness
        .chain
        .inclusion_list_committee(harness.head_block_root(), slot)
        .unwrap();
    assert_eq!(head_dependent_root, block_root_at(dependent_slot));

    let valid = valid_inclusion_list(&harness, slot, block_root_at(dependent_slot), 0xaa);
    assert!(
        harness
            .chain
            .verify_inclusion_list_for_gossip(valid)
            .is_ok()
    );

    let too_recent = valid_inclusion_list(&harness, slot, block_root_at(dependent_slot + 1), 0xaa);
    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(too_recent),
        Err(InclusionListVerificationError::DependentRootTooRecent { .. })
    ));

    // A later block in epoch 0 exists, so this one can't be the dependent block.
    let superseded = valid_inclusion_list(&harness, slot, block_root_at(dependent_slot - 2), 0xaa);
    assert!(matches!(
        harness.chain.verify_inclusion_list_for_gossip(superseded),
        Err(InclusionListVerificationError::InvalidDependentRoot { .. })
    ));
}
