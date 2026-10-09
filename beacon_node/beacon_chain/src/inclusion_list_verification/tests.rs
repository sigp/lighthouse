use std::sync::Arc;
use std::time::Duration;

use slot_clock::{SlotClock, TestingSlotClock};
use ssz_types::ProgressiveVariableList;
use types::{
    Domain, Epoch, EthSpec, Hash256, InclusionList, MinimalEthSpec, ProgressiveTransactions,
    SignedInclusionList, SignedRoot, Slot,
};

use crate::{
    WhenSlotSkipped,
    inclusion_list_store::InsertOutcome,
    inclusion_list_verification::{
        InclusionListVerificationError,
        gossip_verified_inclusion_list::{GossipVerificationContext, GossipVerifiedInclusionList},
    },
    test_utils::{BeaconChainHarness, EphemeralHarnessType, fork_name_from_env, test_spec},
};

type E = MinimalEthSpec;
type T = EphemeralHarnessType<E>;

const NUM_VALIDATORS: usize = 64;

struct TestContext {
    harness: BeaconChainHarness<T>,
    genesis_block_root: Hash256,
}

impl TestContext {
    fn new() -> Self {
        Self::new_with_heze_fork_epoch(Epoch::new(0))
    }

    fn new_with_heze_fork_epoch(heze_fork_epoch: Epoch) -> Self {
        let mut spec = test_spec::<E>();
        spec.heze_fork_epoch = Some(heze_fork_epoch);
        let spec = Arc::new(spec);
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            spec.get_slot_duration(),
        );
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(NUM_VALIDATORS)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(slot_clock)
            .build();

        // Advance past genesis so `now_with_past_tolerance` doesn't underflow.
        harness
            .chain
            .slot_clock
            .set_current_time(harness.spec.get_slot_duration());
        let genesis_block_root = harness.chain.genesis_block_root;

        Self {
            harness,
            genesis_block_root,
        }
    }

    fn gossip_ctx(&self) -> GossipVerificationContext<'_, T> {
        self.harness
            .chain
            .inclusion_list_gossip_verification_context()
    }

    fn current_slot(&self) -> Slot {
        self.harness.chain.slot().expect("should read slot")
    }

    fn committee(&self, slot: Slot) -> Vec<u64> {
        let (committee, _) = self
            .harness
            .chain
            .inclusion_list_committee(self.harness.head_block_root(), slot)
            .expect("should compute committee");
        committee.to_vec()
    }

    fn sign_inclusion_list(&self, message: InclusionList, signer: u64) -> SignedInclusionList {
        let spec = &self.harness.spec;
        let epoch = message.slot.epoch(E::slots_per_epoch());
        let domain = spec.get_domain(
            epoch,
            Domain::InclusionListCommittee,
            &spec.fork_at_epoch(epoch),
            self.harness.chain.genesis_validators_root,
        );
        let signature = self.harness.validator_keypairs[signer as usize]
            .sk
            .sign(message.signing_root(domain));
        SignedInclusionList { message, signature }
    }

    fn valid_inclusion_list(
        &self,
        slot: Slot,
        dependent_root: Hash256,
        txs: Vec<Vec<u8>>,
    ) -> SignedInclusionList {
        let validator_index = self.committee(slot)[0];
        self.sign_inclusion_list(
            make_inclusion_list(slot, validator_index, dependent_root, txs),
            validator_index,
        )
    }
}

fn transactions(txs: Vec<Vec<u8>>) -> ProgressiveTransactions {
    ProgressiveVariableList::new(
        txs.into_iter()
            .map(|tx| ProgressiveVariableList::new(tx).unwrap())
            .collect(),
    )
    .unwrap()
}

fn make_inclusion_list(
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

#[test]
fn valid_inclusion_list() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();

    let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![0xaa]]);
    let verified = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx())
        .expect("should verify inclusion list");
    assert!(verified.is_timely);
    assert_eq!(
        ctx.harness.chain.import_inclusion_list(verified),
        InsertOutcome::New
    );
}

#[test]
fn inclusion_list_after_deadline_is_not_timely() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();
    let slot_clock = &ctx.harness.chain.slot_clock;
    slot_clock.set_current_time(
        slot_clock.start_of(slot).unwrap() + ctx.harness.spec.get_inclusion_list_due(),
    );

    let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![0xaa]]);
    let verified = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx())
        .expect("should verify inclusion list");
    assert!(!verified.is_timely);
}

#[test]
fn already_seen_twice() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();

    // An equivocating second list still counts as a valid message.
    for tx in [0xaa, 0xbb] {
        let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![tx]]);
        let verified = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx())
            .expect("should verify inclusion list");
        ctx.harness.chain.import_inclusion_list(verified);
    }

    let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![0xcc]]);
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::AlreadySeenTwice { .. })
    ));
}

#[test]
fn future_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot() + 1;

    let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![0xaa]]);
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::FutureSlot { .. })
    ));
}

#[test]
fn past_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    ctx.harness.chain.slot_clock.set_slot(5);

    let signed = ctx.valid_inclusion_list(Slot::new(0), ctx.genesis_block_root, vec![vec![0xaa]]);
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::PastSlot { .. })
    ));
}

#[test]
fn slot_within_clock_disparity() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();
    let slot_clock = &ctx.harness.chain.slot_clock;
    let next_slot_start = slot_clock.start_of(slot + 1).unwrap();

    slot_clock.set_current_time(next_slot_start - Duration::from_millis(5));
    let signed = ctx.valid_inclusion_list(slot + 1, ctx.genesis_block_root, vec![vec![0xaa]]);
    let verified = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx())
        .expect("should verify inclusion list for the next slot");
    assert!(!verified.is_timely);

    slot_clock.set_current_time(next_slot_start + Duration::from_millis(5));
    let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![0xaa]]);
    let verified = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx())
        .expect("should verify inclusion list for the previous slot");
    assert!(!verified.is_timely);
}

#[test]
fn rejected_inclusion_list_is_not_counted() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();

    let validator_index = ctx.committee(slot)[0];
    let other_signer = (validator_index + 1) % NUM_VALIDATORS as u64;
    let signed = ctx.sign_inclusion_list(
        make_inclusion_list(
            slot,
            validator_index,
            ctx.genesis_block_root,
            vec![vec![0xaa]],
        ),
        other_signer,
    );
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::InvalidSignature)
    ));

    for tx in [0xaa, 0xbb] {
        let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![tx]]);
        let verified = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx())
            .expect("should verify inclusion list");
        ctx.harness.chain.import_inclusion_list(verified);
    }
}

#[test]
fn empty_transactions() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();

    // A list of only empty transactions also has a total size of zero, so it is ignored.
    for txs in [vec![], vec![vec![]]] {
        let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, txs);
        let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
        assert!(matches!(
            result,
            Err(InclusionListVerificationError::EmptyTransactions)
        ));
    }
}

#[test]
fn invalid_transactions() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();
    let max_size = ctx.harness.spec.max_transactions_bytes_per_inclusion_list as usize;

    for txs in [vec![vec![0xaa; max_size + 1]], vec![vec![0xaa], vec![]]] {
        let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, txs);
        let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
        assert!(matches!(
            result,
            Err(InclusionListVerificationError::InvalidTransactions(_))
        ));
    }
}

#[test]
fn transactions_at_size_limit() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();
    let max_size = ctx.harness.spec.max_transactions_bytes_per_inclusion_list as usize;

    let signed = ctx.valid_inclusion_list(slot, ctx.genesis_block_root, vec![vec![0xaa; max_size]]);
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);
}

#[test]
fn unknown_dependent_root() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();

    let signed = ctx.valid_inclusion_list(slot, Hash256::repeat_byte(0xff), vec![vec![0xaa]]);
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::DependentRootUnknown { .. })
    ));
}

#[test]
fn not_in_committee() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();

    let committee = ctx.committee(slot);
    let non_member = (0..NUM_VALIDATORS as u64)
        .find(|index| !committee.contains(index))
        .expect("should find a non-member");
    let signed = ctx.sign_inclusion_list(
        make_inclusion_list(slot, non_member, ctx.genesis_block_root, vec![vec![0xaa]]),
        non_member,
    );
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::NotInCommittee { .. })
    ));
}

#[test]
fn invalid_signature() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = ctx.current_slot();

    let validator_index = ctx.committee(slot)[0];
    let other_signer = (validator_index + 1) % NUM_VALIDATORS as u64;
    let signed = ctx.sign_inclusion_list(
        make_inclusion_list(
            slot,
            validator_index,
            ctx.genesis_block_root,
            vec![vec![0xaa]],
        ),
        other_signer,
    );
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::InvalidSignature)
    ));
}

/// For a slot in epoch 2, the dependent block is the last block of epoch 0.
#[tokio::test]
async fn dependent_root_must_be_the_shuffling_dependent_block() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = Slot::new(2 * E::slots_per_epoch());
    ctx.harness.extend_to_slot(slot).await;
    let dependent_slot = Slot::new(E::slots_per_epoch() - 1);
    let block_root_at = |slot: Slot| {
        ctx.harness
            .chain
            .block_root_at_slot(slot, WhenSlotSkipped::None)
            .unwrap()
            .unwrap()
    };

    let valid = ctx.valid_inclusion_list(slot, block_root_at(dependent_slot), vec![vec![0xaa]]);
    let result = GossipVerifiedInclusionList::new(valid, &ctx.gossip_ctx());
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);

    let too_recent =
        ctx.valid_inclusion_list(slot, block_root_at(dependent_slot + 1), vec![vec![0xaa]]);
    let result = GossipVerifiedInclusionList::new(too_recent, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::DependentRootTooRecent { .. })
    ));

    // Its only child sits at the dependent slot, so this one can't be the dependent block.
    let superseded =
        ctx.valid_inclusion_list(slot, block_root_at(dependent_slot - 1), vec![vec![0xaa]]);
    let result = GossipVerifiedInclusionList::new(superseded, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::InvalidDependentRoot { .. })
    ));
}

/// A list built on a side chain is checked against that chain's committee.
#[tokio::test]
async fn side_chain_inclusion_list_uses_side_chain_committee() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let harness = &ctx.harness;
    let fork_slot = Slot::new(E::slots_per_epoch());
    let slot = Slot::new(4 * E::slots_per_epoch());

    harness.extend_to_slot(fork_slot).await;
    let fork_state = harness.chain.head_snapshot().beacon_state.clone();

    // The side chain skips a slot, so its RANDAO mixes and committees differ. Only the
    // canonical chain is attested to, so it stays the head without finalizing past the fork.
    let side_slots = ((fork_slot + 2).as_u64()..=slot.as_u64())
        .map(Slot::new)
        .collect();
    let canonical_slots = ((fork_slot + 1).as_u64()..=slot.as_u64())
        .map(Slot::new)
        .collect();
    let results = harness
        .add_blocks_on_multiple_chains(vec![
            (fork_state.clone(), side_slots, vec![]),
            (
                fork_state,
                canonical_slots,
                (0..NUM_VALIDATORS / 2).collect(),
            ),
        ])
        .await;
    let side_head_root: Hash256 = results[0].2.into();
    let canonical_head_root: Hash256 = results[1].2.into();
    assert_eq!(harness.head_block_root(), canonical_head_root);
    harness.chain.slot_clock.set_slot(slot.as_u64());

    let committee_and_dependent_root = |head_root| {
        let (committee, dependent_root) = harness
            .chain
            .inclusion_list_committee(head_root, slot)
            .expect("should compute committee");
        (committee.to_vec(), dependent_root)
    };
    let (side_committee, side_dependent_root) = committee_and_dependent_root(side_head_root);
    let (canonical_committee, _) = committee_and_dependent_root(canonical_head_root);
    assert_ne!(side_committee, canonical_committee);

    let side_member = *side_committee
        .iter()
        .find(|index| !canonical_committee.contains(index))
        .expect("should find a member of the side chain committee only");
    let signed = ctx.sign_inclusion_list(
        make_inclusion_list(slot, side_member, side_dependent_root, vec![vec![0xaa]]),
        side_member,
    );
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);

    let canonical_member = *canonical_committee
        .iter()
        .find(|index| !side_committee.contains(index))
        .expect("should find a member of the canonical committee only");
    let signed = ctx.sign_inclusion_list(
        make_inclusion_list(
            slot,
            canonical_member,
            side_dependent_root,
            vec![vec![0xaa]],
        ),
        canonical_member,
    );
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::NotInCommittee { .. })
    ));
}

/// In the first Heze epoch the dependent block is a Gloas block, and the list is signed with the
/// Heze fork version.
#[tokio::test]
async fn inclusion_list_in_first_heze_epoch() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let heze_fork_epoch = Epoch::new(2);
    let ctx = TestContext::new_with_heze_fork_epoch(heze_fork_epoch);
    let slot = heze_fork_epoch.start_slot(E::slots_per_epoch());
    ctx.harness.extend_to_slot(slot).await;

    let (committee, dependent_root) = ctx
        .harness
        .chain
        .inclusion_list_committee(ctx.harness.head_block_root(), slot)
        .expect("should compute committee");
    let dependent_slot = ctx
        .harness
        .chain
        .get_blinded_block(&dependent_root)
        .unwrap()
        .unwrap()
        .slot();
    assert!(
        !ctx.harness
            .spec
            .fork_name_at_slot::<E>(dependent_slot)
            .heze_enabled()
    );

    let validator_index = committee[0];
    let signed = ctx.sign_inclusion_list(
        make_inclusion_list(slot, validator_index, dependent_root, vec![vec![0xaa]]),
        validator_index,
    );
    let result = GossipVerifiedInclusionList::new(signed, &ctx.gossip_ctx());
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);
}
