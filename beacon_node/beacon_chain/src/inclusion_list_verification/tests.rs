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
        let mut spec = test_spec::<E>();
        spec.heze_fork_epoch = Some(Epoch::new(0));
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

    // A later block in epoch 0 exists, so this one can't be the dependent block.
    let superseded =
        ctx.valid_inclusion_list(slot, block_root_at(dependent_slot - 2), vec![vec![0xaa]]);
    let result = GossipVerifiedInclusionList::new(superseded, &ctx.gossip_ctx());
    assert!(matches!(
        result,
        Err(InclusionListVerificationError::InvalidDependentRoot { .. })
    ));
}
