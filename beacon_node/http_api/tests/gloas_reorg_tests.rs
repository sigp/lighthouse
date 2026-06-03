//! post-gloas payload re-org tests.
//!
//! These tests are deliberately kept separate from `interactive_tests.rs` because they exercise
//! post-gloas fork-choice behaviour: the head is a `ForkChoiceNode` = (block root, payload status),
//! and a block's *payload* can be re-orged (head flips `FULL` -> `EMPTY`) independently of the
//! beacon block, when later-slot voters attest the block with `payload_present = false`.
//!
use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy, LightClientStrategy, SyncCommitteeStrategy},
    custody_context::NodeCustodyType,
};
use fixed_bytes::FixedBytesExtended;
use http_api::test_utils::InteractiveTester;
use proto_array::PayloadStatus;
use state_processing::state_advance::complete_state_advance;
use std::sync::Arc;
use types::{
    Address, EthSpec, ForkName, Hash256, MainnetEthSpec, ProposerPreparationData, Slot, Uint256,
};

type E = MainnetEthSpec;

const ATTESTERS_PER_SLOT: usize = 10;

/// Gloas-from-genesis spec used by all tests in this module.
fn gloas_test_spec() -> types::ChainSpec {
    let mut spec = ForkName::latest().make_genesis_spec(E::default_spec());
    spec.terminal_total_difficulty = Uint256::from(1);
    spec
}

/// Common harness preparation shared by the Gloas re-org tests: mark mock payloads valid, register
/// proposer preparation data for all validators, then build `num_initial` blocks of chain depth.
///
/// `prep_slot` is the slot of the block the test cares about; proposer preparation is registered for
/// its epoch + 1 (matching the lookahead the real node uses).
async fn prepare_gloas_chain(
    tester: &InteractiveTester<E>,
    validator_count: usize,
    num_initial: u64,
    prep_slot: Slot,
) {
    let harness = &tester.harness;
    harness
        .mock_execution_layer
        .as_ref()
        .unwrap()
        .server
        .all_payloads_valid();

    let proposer_preparation_data = (0..validator_count)
        .map(|i| {
            (
                ProposerPreparationData {
                    validator_index: i as u64,
                    fee_recipient: Address::from_low_u64_be(i as u64),
                },
                None,
            )
        })
        .collect::<Vec<_>>();
    harness
        .chain
        .execution_layer
        .as_ref()
        .unwrap()
        .update_proposer_preparation(
            prep_slot.epoch(E::slots_per_epoch()) + 1,
            proposer_preparation_data.iter().map(|(a, b)| (a, b)),
        )
        .await;

    harness.advance_slot();
    harness
        .extend_chain_with_sync(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
            SyncCommitteeStrategy::AllValidators,
            LightClientStrategy::Disabled,
        )
        .await;
}

/// Parameters for a single Gloas re-org scenario.
/// Payload re-org (flavor A): a block `B` whose execution payload *is* delivered (so its `FULL`
/// node exists in fork choice) can still have its payload orphaned if later-slot voters attest to
/// `B` with `payload_present = false`. Those votes land in `B`'s `EMPTY` payload bucket, so
/// `get_head` prefers `(B, EMPTY)` over `(B, FULL)` — the beacon block stays canonical but its
/// payload is re-orged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gloas_payload_reorg_head_flips_to_empty_when_voters_attest_empty() {
    let validator_count = E::slots_per_epoch() as usize * ATTESTERS_PER_SLOT;
    let all_validators = (0..validator_count).collect::<Vec<usize>>();

    // Keep B and the later votes comfortably inside one epoch.
    let slot_b = Slot::new(E::slots_per_epoch() - 4);
    let num_initial = slot_b.as_u64() - 1;

    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(gloas_test_spec()),
        validator_count,
        None,
        None,
        Default::default(),
        false,
        NodeCustodyType::Fullnode,
    )
    .await;
    prepare_gloas_chain(&tester, validator_count, num_initial, slot_b).await;
    let harness = &tester.harness;

    // Produce B at `slot_b`. `add_block_at_slot` also delivers and verifies B's payload envelope, so
    // B's `FULL` node exists in fork choice and B is the canonical head on the `FULL` path.
    harness.advance_slot();
    let (block_b_root, _block_b, mut state_b) = harness
        .add_block_at_slot(slot_b, harness.get_current_state())
        .await
        .unwrap();
    let state_b_root = state_b.canonical_root().unwrap();

    assert_eq!(harness.head_block_root(), Hash256::from(block_b_root));
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_payload_status(),
        PayloadStatus::Full,
        "B's delivered payload should make the head FULL before any EMPTY votes"
    );

    // Cast later-slot (slot_b + 1) votes for B with `payload_present = false`, forcing them into
    // B's EMPTY payload bucket.
    let slot_b1 = slot_b + 1;
    harness.advance_slot();
    let fork = harness
        .spec
        .fork_at_epoch(slot_b1.epoch(E::slots_per_epoch()));
    let (empty_votes, _) = harness.make_attestations_with_payload_present_override(
        &all_validators,
        &state_b,
        state_b_root,
        block_b_root.into(),
        slot_b1,
        fork,
        false,
    );
    harness.process_attestations(empty_votes, &state_b);

    // Advance one more slot so the `slot_b + 1` votes are applied to fork choice, then recompute.
    harness.advance_slot();
    harness
        .chain
        .recompute_head_at_slot(slot_b + 2)
        .await;

    assert_eq!(
        harness.head_block_root(),
        Hash256::from(block_b_root),
        "B should remain the canonical beacon block (only the payload is re-orged)"
    );
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_payload_status(),
        PayloadStatus::Empty,
        "EMPTY-bucket votes should orphan B's payload (payload re-org)"
    );

    //TODO(manas): produce block
}

/// Payload re-org (flavor B): once `B`'s payload is orphaned (head is `(B, EMPTY)` despite the
/// payload being delivered, as in flavor A), the next proposer `C` builds on `B`'s EMPTY path. The
/// beacon block `B` is kept as `C`'s parent, but `C`'s bid does not extend `B`'s execution payload —
/// it points back at `B`'s parent's payload, i.e. the payload is re-orged out by the proposer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gloas_payload_reorg_proposer_builds_on_empty_path() {
    let validator_count = E::slots_per_epoch() as usize * ATTESTERS_PER_SLOT;
    let all_validators = (0..validator_count).collect::<Vec<usize>>();

    let slot_b = Slot::new(E::slots_per_epoch() - 4);
    let num_initial = slot_b.as_u64() - 1;
    let slot_c = slot_b + 2;

    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(gloas_test_spec()),
        validator_count,
        None,
        None,
        Default::default(),
        false,
        NodeCustodyType::Fullnode,
    )
    .await;
    prepare_gloas_chain(&tester, validator_count, num_initial, slot_b).await;
    let harness = &tester.harness;

    // Produce B with its payload delivered (FULL node exists, B is the FULL head).
    harness.advance_slot();
    let (block_b_root, block_b, mut state_b) = harness
        .add_block_at_slot(slot_b, harness.get_current_state())
        .await
        .unwrap();
    let state_b_root = state_b.canonical_root().unwrap();

    // `B`'s own committed execution payload hash. If `C` extends `B`'s payload its bid would point
    // at this; a payload re-org means it must not.
    let block_b_payload_hash = block_b
        .0
        .message()
        .body()
        .signed_execution_payload_bid()
        .expect("Gloas block should have a payload bid")
        .message
        .block_hash;

    // Orphan B's payload: later-slot voters attest B with `payload_present = false`.
    let slot_b1 = slot_b + 1;
    harness.advance_slot();
    let fork = harness
        .spec
        .fork_at_epoch(slot_b1.epoch(E::slots_per_epoch()));
    let (empty_votes, _) = harness.make_attestations_with_payload_present_override(
        &all_validators,
        &state_b,
        state_b_root,
        block_b_root.into(),
        slot_b1,
        fork,
        false,
    );
    harness.process_attestations(empty_votes, &state_b);

    harness.advance_slot();
    harness.chain.recompute_head_at_slot(slot_c).await;

    // Sanity: head is `(B, EMPTY)`.
    assert_eq!(harness.head_block_root(), Hash256::from(block_b_root));
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_payload_status(),
        PayloadStatus::Empty,
    );

    // Produce C at `slot_c`.
    complete_state_advance(&mut state_b, None, slot_c, &harness.chain.spec).unwrap();
    let proposer_index = state_b
        .get_beacon_proposer_index(slot_c, &harness.chain.spec)
        .unwrap();
    let randao_reveal = harness
        .sign_randao_reveal(&state_b, proposer_index, slot_c)
        .into();
    let (response, _) = tester
        .client
        .get_validator_blocks_v4::<E>(slot_c, &randao_reveal, None, None, None, None)
        .await
        .unwrap();
    let block_c = Arc::new(harness.sign_beacon_block(response.data, &state_b));

    // C keeps B as its beacon-block parent (no *block* re-org)...
    assert_eq!(
        block_c.parent_root(),
        Hash256::from(block_b_root),
        "C should still build on beacon block B"
    );

    // ...but builds on B's EMPTY payload path: its bid does not extend B's execution payload.
    let block_c_parent_payload_hash = block_c
        .message()
        .body()
        .signed_execution_payload_bid()
        .expect("Gloas block should have a payload bid")
        .message
        .parent_block_hash;
    assert_ne!(
        block_c_parent_payload_hash, block_b_payload_hash,
        "C must not extend B's payload — B's payload is re-orged"
    );

    // TODO:
    // 1. get_proposer_head=grand-parent (do-reorg) + payload_status=empty
    // 1. get_proposer_head=grant-parent (do-reorg) + payload_status=full
    // 1. get_proposer_head=parent (don't-reorg) + payload_status=full
    // 1. get_proposer_head=parent (don't-reorg) + payload_status=empty
    //
    // should make sure that all existing test pass
    // - run each for gloas and understand what changes are needed to make them pass for gloas
    // - some tests might require gloas-specfic setup changes:
}
