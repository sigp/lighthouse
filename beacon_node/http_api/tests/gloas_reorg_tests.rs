//! post-gloas payload re-org tests.
//!
//! These tests are deliberately kept separate from `interactive_tests.rs` because they exercise
//! post-gloas fork-choice behaviour: the head is a `ForkChoiceNode` = (block root, payload status),
//! and a block's *payload* can be re-orged (head flips `FULL` -> `EMPTY`) independently of the
//! beacon block, when later-slot voters attest the block with `payload_present = false`.
//!
use beacon_chain::{
    ChainConfig,
    chain_config::DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR,
    custody_context::NodeCustodyType,
    test_utils::{
        AttestationStrategy, BlockStrategy, LightClientStrategy, MakeAttestationOptions,
        MakePayloadAttestationOptions, PayloadAttestationVote, SyncCommitteeStrategy, test_spec,
    },
};
use eth2::types::ProduceBlockV3Response;
use execution_layer::{ForkchoiceState, PayloadAttributes};
use fixed_bytes::FixedBytesExtended;
use http_api::test_utils::InteractiveTester;
use parking_lot::Mutex;
use proto_array::PayloadStatus;
use slot_clock::SlotClock;
use state_processing::{
    per_block_processing::get_expected_withdrawals, state_advance::complete_state_advance,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use types::{
    Address, BeaconBlockRef, EthSpec, ExecPayload, ExecutionBlockHash, Hash256, MinimalEthSpec,
    ProposerPreparationData, Slot,
};

type E = MinimalEthSpec;

// Must be at least PTC size to simplify PTC reasoning (unique PTC members per slot).
const ATTESTERS_PER_SLOT: usize = 20;

/// Data structure for tracking fork choice updates received by the mock execution layer.
#[derive(Debug, Default)]
struct ForkChoiceUpdates {
    updates: HashMap<ExecutionBlockHash, Vec<ForkChoiceUpdateMetadata>>,
}

#[derive(Debug, Clone)]
struct ForkChoiceUpdateMetadata {
    received_at: Duration,
    state: ForkchoiceState,
    payload_attributes: Option<PayloadAttributes>,
}

impl ForkChoiceUpdates {
    fn insert(&mut self, update: ForkChoiceUpdateMetadata) {
        self.updates
            .entry(update.state.head_block_hash)
            .or_default()
            .push(update);
    }

    fn contains_update_for(&self, block_hash: ExecutionBlockHash) -> bool {
        self.updates.contains_key(&block_hash)
    }

    /// Find the first fork choice update for `head_block_hash` with payload attributes matching
    /// the proposal and parent being tested.
    fn first_update_with_payload_attributes(
        &self,
        head_block_hash: ExecutionBlockHash,
        proposal_timestamp: u64,
        parent_beacon_block_root: Option<Hash256>,
        slot_number: Option<u64>,
    ) -> Option<ForkChoiceUpdateMetadata> {
        self.updates
            .get(&head_block_hash)?
            .iter()
            .find(|update| {
                update
                    .payload_attributes
                    .as_ref()
                    .is_some_and(|payload_attributes| {
                        if payload_attributes.timestamp() != proposal_timestamp {
                            return false;
                        }

                        if let Some(parent_beacon_block_root) = parent_beacon_block_root
                            && payload_attributes.parent_beacon_block_root().ok()
                                != Some(parent_beacon_block_root)
                        {
                            return false;
                        }

                        if let Some(slot_number) = slot_number
                            && payload_attributes.slot_number().ok() != Some(slot_number)
                        {
                            return false;
                        }

                        true
                    })
            })
            .cloned()
    }
}

#[derive(Clone, Copy)]
enum ExpectedFirstUpdateLookahead {
    Payload,
    ForkChoice,
    BlockProduction,
}

pub struct ReOrgTest {
    head_slot: Slot,
    /// Number of slots between parent block and canonical head.
    parent_distance: u64,
    /// Number of slots between head block and block proposal slot.
    head_distance: u64,
    /// Fraction of parent (A)'s committee that votes for A (always with payload_present=0).
    percent_parent_votes: usize,
    /// Fraction of B's committee that votes for A with payload_present=0.
    percent_skip_empty_votes: usize,
    /// Fraction of B's committee that votes for A with payload_present=1.
    percent_skip_full_votes: usize,
    /// Fraction of B's committee that votes for B (always with payload_present=0).
    percent_head_votes: usize,
    /// Parent payload status of block B.
    head_parent_payload_status: PayloadStatus,
    /// Fraction of A's PTC that vote for A's payload being present.
    percent_parent_ptc_present_votes: usize,
    /// Fraction of A's PTC that vote for A's payload being absent.
    percent_parent_ptc_absent_votes: usize,
    /// Expected parent payload status of our proposed block (C).
    ///
    /// This can be the payload status of A or B depending on whether we reorged or not.
    expected_parent_payload_status: PayloadStatus,
    should_re_org: bool,
    expected_first_update_lookahead: ExpectedFirstUpdateLookahead,
    /// Whether to expect withdrawals to change on epoch boundaries.
    expect_withdrawals_change_on_epoch: bool,
}

impl Default for ReOrgTest {
    /// Default config represents a regular easy re-org.
    fn default() -> Self {
        Self {
            head_slot: Slot::new(E::slots_per_epoch() - 2),
            parent_distance: 1,
            head_distance: 1,
            percent_parent_votes: 100,
            percent_skip_empty_votes: 0,
            percent_skip_full_votes: 100,
            percent_head_votes: 0,
            head_parent_payload_status: PayloadStatus::Full,
            percent_parent_ptc_present_votes: 100,
            percent_parent_ptc_absent_votes: 0,
            expected_parent_payload_status: PayloadStatus::Full,
            should_re_org: true,
            expected_first_update_lookahead: ExpectedFirstUpdateLookahead::Payload,
            expect_withdrawals_change_on_epoch: false,
        }
    }
}

// This test doesn't actually exercise the re-org code path because the chain just naturally
// re-orgs to A-empty at the start of slot C anyway. That only happens after the 500ms
// pre-slot fork choice recompute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn re_org_parent_is_empty_easy() {
    proposer_boost_re_org_test(ReOrgTest {
        percent_skip_empty_votes: 100,
        percent_skip_full_votes: 0,
        expected_parent_payload_status: PayloadStatus::Empty,
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::ForkChoice,
        ..Default::default()
    })
    .await;
}

// A-Empty chain has 55% of one committee supporting it A-Full chain has 45% of one committee
// supporting it, including 15% for descendant B that is late and re-orgable.
//
// A-Full has 100% PTC support, but this should be completely ignored.
//
// We should re-org B and build on A-Empty.
//
// This test doesn't actually exercise the re-org code path because the chain just naturally
// re-orgs to A-empty at the start of slot C anyway. That only happens after the 500ms
// pre-slot fork choice recompute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn re_org_parent_is_empty_marginal_win() {
    proposer_boost_re_org_test(ReOrgTest {
        percent_skip_empty_votes: 55,
        percent_skip_full_votes: 30,
        percent_head_votes: 15,
        percent_parent_ptc_present_votes: 100,
        percent_parent_ptc_absent_votes: 0,
        expected_parent_payload_status: PayloadStatus::Empty,
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::ForkChoice,
        ..Default::default()
    })
    .await;
}

// A-Empty chain has 45% of one committee supporting it A-Full chain has 55% of one committee
// supporting it, including 15% for descendant B that is late and re-orgable.
//
// A-Full has 100% PTC support, but this should be completely ignored.
//
// We should re-org B and build on A-Full.
// Since Gloas fork choice updates are not overridden for proposer re-orgs, the first fcU for this
// parent is sent during block production.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn re_org_parent_is_full_marginal_win() {
    proposer_boost_re_org_test(ReOrgTest {
        percent_skip_empty_votes: 45,
        percent_skip_full_votes: 40,
        percent_head_votes: 15,
        percent_parent_ptc_present_votes: 100,
        percent_parent_ptc_absent_votes: 0,
        expected_parent_payload_status: PayloadStatus::Full,
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::BlockProduction,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_parent_empty() {
    proposer_boost_re_org_test(ReOrgTest {
        percent_skip_empty_votes: 55,
        percent_skip_full_votes: 30,
        percent_head_votes: 15,
        percent_parent_ptc_present_votes: 100,
        percent_parent_ptc_absent_votes: 0,
        head_parent_payload_status: PayloadStatus::Empty,
        expected_parent_payload_status: PayloadStatus::Empty,
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::BlockProduction,
        ..Default::default()
    })
    .await;
}

// Test that the beacon node will try to perform proposer boost re-orgs on late blocks when
// configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_zero_weight() {
    proposer_boost_re_org_test(ReOrgTest {
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::BlockProduction,
        ..Default::default()
    })
    .await;
}

// Since Fulu, proposer shuffling is stable across epoch boundaries, so re-orgs of the last block
// in an epoch are permitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_epoch_boundary() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() - 1),
        should_re_org: true,
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::BlockProduction,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_epoch_boundary_skip1() {
    // Proposing a block on a boundary after a skip will change the set of expected withdrawals
    // sent in the payload attributes.
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(2 * E::slots_per_epoch() - 2),
        head_distance: 2,
        should_re_org: false,
        expect_withdrawals_change_on_epoch: true,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_epoch_boundary_skip32() {
    // Propose a block at 64 after a whole epoch of skipped slots.
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() - 1),
        head_distance: E::slots_per_epoch() + 1,
        should_re_org: false,
        expect_withdrawals_change_on_epoch: true,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_slot_after_epoch_boundary() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(33),
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::BlockProduction,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_bad_ffg() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(64 + 22),
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_no_finality() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(96),
        percent_parent_votes: 100,
        percent_skip_full_votes: 0,
        percent_head_votes: 100,
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_finality() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(129),
        expected_first_update_lookahead: ExpectedFirstUpdateLookahead::BlockProduction,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_parent_distance() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() - 2),
        parent_distance: 2,
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_head_distance() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() - 3),
        head_distance: 2,
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_very_unhealthy() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() - 1),
        parent_distance: 2,
        head_distance: 2,
        percent_parent_votes: 10,
        percent_skip_full_votes: 10,
        percent_head_votes: 10,
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

/// The head block is late but still receives 30% of the committee vote, making it strong enough
/// that we do not re-org it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_head_too_strong() {
    proposer_boost_re_org_test(ReOrgTest {
        percent_skip_full_votes: 70,
        percent_head_votes: 30,
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

/// Run a proposer boost re-org test.
///
/// - `head_slot`: the slot of the canonical head to be reorged
/// - `reorg_threshold`: committee percentage value for reorging
/// - `num_empty_votes`: percentage of comm of attestations for the parent block
/// - `num_head_votes`: number of attestations for the head block
/// - `should_re_org`: whether the proposer should build on the parent rather than the head
#[allow(clippy::large_stack_frames)]
pub async fn proposer_boost_re_org_test(
    ReOrgTest {
        head_slot,
        parent_distance,
        head_distance,
        percent_parent_votes,
        percent_skip_empty_votes,
        percent_skip_full_votes,
        percent_head_votes,
        head_parent_payload_status,
        percent_parent_ptc_present_votes,
        percent_parent_ptc_absent_votes,
        expected_parent_payload_status,
        should_re_org,
        expected_first_update_lookahead,
        expect_withdrawals_change_on_epoch,
    }: ReOrgTest,
) {
    assert!(head_slot > 0);

    let spec = test_spec::<E>();

    if !spec.is_gloas_scheduled() {
        return;
    }

    // Ensure there are enough validators to have `ATTESTERS_PER_SLOT`.
    assert!(ATTESTERS_PER_SLOT >= E::ptc_size());
    let validator_count = E::slots_per_epoch() as usize * ATTESTERS_PER_SLOT;
    let all_validators = (0..validator_count).collect::<Vec<usize>>();
    let num_initial = head_slot.as_u64().checked_sub(parent_distance + 1).unwrap();

    // Check that the required vote percentages can be satisfied exactly using `ATTESTERS_PER_SLOT`.
    assert_eq!(100 % ATTESTERS_PER_SLOT, 0);
    let percent_per_attester = 100 / ATTESTERS_PER_SLOT;
    assert_eq!(percent_parent_votes % percent_per_attester, 0);
    assert_eq!(percent_skip_empty_votes % percent_per_attester, 0);
    assert_eq!(percent_skip_full_votes % percent_per_attester, 0);
    assert_eq!(percent_head_votes % percent_per_attester, 0);
    let num_parent_votes = Some(ATTESTERS_PER_SLOT * percent_parent_votes / 100);
    let num_skip_empty_votes = Some(ATTESTERS_PER_SLOT * percent_skip_empty_votes / 100);
    let num_skip_full_votes = Some(ATTESTERS_PER_SLOT * percent_skip_full_votes / 100);
    let num_head_votes = Some(ATTESTERS_PER_SLOT * percent_head_votes / 100);

    assert_eq!((percent_parent_ptc_present_votes * E::ptc_size()) % 100, 0);
    let num_parent_ptc_present_votes = percent_parent_ptc_present_votes * E::ptc_size() / 100;
    assert_eq!((percent_parent_ptc_absent_votes * E::ptc_size()) % 100, 0);
    let num_parent_ptc_absent_votes = percent_parent_ptc_absent_votes * E::ptc_size() / 100;

    // We must configure the prepare payload lookahead so it scales with the minimal config,
    // otherwise the late block reveal for A halfway through the slot can end up being *after*
    // the payload lookahead, which messes up our measurement of timings.
    let chain_config = ChainConfig {
        prepare_payload_lookahead: spec.get_slot_duration()
            / DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR,
        ..Default::default()
    };

    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(spec),
        validator_count,
        None,
        Some(Box::new(move |builder| builder.chain_config(chain_config))),
        Default::default(),
        false,
        NodeCustodyType::Fullnode,
    )
    .await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();
    let execution_ctx = mock_el.server.ctx.clone();
    let slot_clock = &harness.chain.slot_clock;

    mock_el.server.all_payloads_valid();

    // Send proposer preparation data for all validators.
    let proposer_preparation_data = all_validators
        .iter()
        .map(|i| {
            (
                ProposerPreparationData {
                    validator_index: *i as u64,
                    fee_recipient: Address::from_low_u64_be(*i as u64),
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
            head_slot.epoch(E::slots_per_epoch()) + 1,
            proposer_preparation_data.iter().map(|(a, b)| (a, b)),
        )
        .await;

    // Create some chain depth. Sign sync committee signatures so validator balances don't dip
    // below 32 ETH and become ineligible for withdrawals.
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

    // Start collecting fork choice updates.
    let forkchoice_updates = Arc::new(Mutex::new(ForkChoiceUpdates::default()));
    let forkchoice_updates_inner = forkchoice_updates.clone();
    let chain_inner = harness.chain.clone();

    execution_ctx
        .hook
        .lock()
        .set_forkchoice_updated_hook(Box::new(move |state, payload_attributes| {
            let received_at = chain_inner.slot_clock.now_duration().unwrap();
            let state = ForkchoiceState::from(state);
            let payload_attributes = payload_attributes.map(Into::into);
            let update = ForkChoiceUpdateMetadata {
                received_at,
                state,
                payload_attributes,
            };
            forkchoice_updates_inner.lock().insert(update);
            None
        }));

    // We set up the following block graph, where B is a block that arrives late and is re-orged
    // by C.
    //
    // A | B | - |
    // ^ | - | C |

    let slot_a = Slot::new(num_initial + 1);
    let slot_b = slot_a + parent_distance;
    let slot_c = slot_b + head_distance;

    // We need to transition to at least epoch 2 in order to trigger
    // `process_rewards_and_penalties`. This allows us to test withdrawals changes at epoch
    // boundaries.
    if expect_withdrawals_change_on_epoch {
        assert!(
            slot_c.epoch(E::slots_per_epoch()) >= 2,
            "for withdrawals to change, test must end at an epoch >= 2"
        );
    }

    harness.advance_slot();
    let (block_a_root, block_a, mut state_a) = harness
        .add_block_at_slot(slot_a, harness.get_current_state())
        .await
        .unwrap();
    let state_a_root = state_a.canonical_root().unwrap();

    // Attest to block A during slot A.
    let (block_a_parent_votes, _) = harness.make_attestations_with_limit(
        &all_validators,
        &state_a,
        state_a_root,
        block_a_root,
        slot_a,
        num_parent_votes,
    );
    harness.process_attestations(block_a_parent_votes, &state_a);

    // Produce PTC messages for slot A.
    let a_ptc_votes = vec![
        PayloadAttestationVote {
            validator_count: num_parent_ptc_present_votes,
            payload_present: true,
            blob_data_available: true,
        },
        PayloadAttestationVote {
            validator_count: num_parent_ptc_absent_votes,
            payload_present: false,
            blob_data_available: false,
        },
    ];
    let (a_ptc_messages, _) = harness.make_payload_attestation_messages_with_opts(
        &all_validators,
        &state_a,
        block_a_root.into(),
        slot_a,
        MakePayloadAttestationOptions {
            votes: a_ptc_votes,
            fork: state_a.fork(),
        },
    );
    harness
        .import_payload_attestation_messages(a_ptc_messages)
        .unwrap();

    // Attest to block A during slot B.
    for _ in 0..parent_distance {
        harness.advance_slot();
    }
    let (block_a_empty_votes, block_a_empty_attesters) = harness.make_attestations_with_opts(
        &all_validators,
        &state_a,
        state_a_root,
        block_a_root,
        slot_b,
        MakeAttestationOptions {
            limit: num_skip_empty_votes,
            fork: state_a.fork(),
            payload_present_override: Some(false),
        },
    );
    harness.process_attestations(block_a_empty_votes, &state_a);
    let remaining_attesters_after_empty = all_validators
        .iter()
        .copied()
        .filter(|index| !block_a_empty_attesters.contains(index))
        .collect::<Vec<_>>();
    let (block_a_full_votes, block_a_full_attesters) = harness.make_attestations_with_opts(
        &remaining_attesters_after_empty,
        &state_a,
        state_a_root,
        block_a_root,
        slot_b,
        MakeAttestationOptions {
            limit: num_skip_full_votes,
            fork: state_a.fork(),
            payload_present_override: Some(true),
        },
    );
    harness.process_attestations(block_a_full_votes, &state_a);

    let remaining_attesters = remaining_attesters_after_empty
        .iter()
        .copied()
        .filter(|index| !block_a_full_attesters.contains(index))
        .collect::<Vec<_>>();

    // Produce block B and process it halfway through the slot.
    // When B is expected to remain canonical (no re-org), capture its Gloas payload envelope so we
    // can reveal B's execution payload to fork choice below. Without this, B's payload status stays
    // `Empty`/`Pending` and the forkchoiceUpdated head hash falls back to B's parent rather than B's
    // own execution block hash. We skip this when B will be re-orged, since the execution layer
    // must never be told about a block that is about to be re-orged away.
    let is_gloas = harness
        .chain
        .spec
        .fork_name_at_slot::<E>(slot_b)
        .gloas_enabled();
    let reveal_block_b_payload = is_gloas && !should_re_org;
    let (block_b, block_b_envelope, mut state_b) = if is_gloas {
        let (block_b, block_b_envelope, state_b) = harness
            .make_block_with_envelope_on(state_a.clone(), slot_b, head_parent_payload_status)
            .await;
        let block_b_envelope = if reveal_block_b_payload {
            block_b_envelope
        } else {
            None
        };
        (block_b, block_b_envelope, state_b)
    } else {
        let (block_b, state_b) = harness.make_block(state_a.clone(), slot_b).await;
        (block_b, None, state_b)
    };
    let state_b_root = state_b.canonical_root().unwrap();
    let block_b_root = block_b.0.canonical_root();

    let obs_time = slot_clock.start_of(slot_b).unwrap() + slot_clock.slot_duration() / 2;
    slot_clock.set_current_time(obs_time);
    harness.chain.block_times_cache.write().set_time_observed(
        block_b_root,
        slot_b,
        obs_time,
        None,
        None,
    );
    harness.process_block_result(block_b.clone()).await.unwrap();

    // Reveal B's execution payload so fork choice marks the payload as received and the
    // forkchoiceUpdated head hash references B's own execution block hash.
    if let Some(block_b_envelope) = block_b_envelope {
        harness
            .process_envelope(block_b_root, block_b_envelope, &state_b, state_b_root)
            .await;
    }

    // Add attestations to block B.
    let (block_b_head_votes, _) = harness.make_attestations_with_limit(
        &remaining_attesters,
        &state_b,
        state_b_root,
        block_b_root.into(),
        slot_b,
        num_head_votes,
    );
    harness.process_attestations(block_b_head_votes, &state_b);

    let payload_lookahead = harness.chain.config.prepare_payload_lookahead;
    let fork_choice_lookahead = Duration::from_millis(500);
    while harness.get_current_slot() != slot_c {
        let current_slot = harness.get_current_slot();
        let next_slot = current_slot + 1;

        // Simulate the scheduled call to prepare proposers at 8 seconds into the slot.
        harness.advance_to_slot_lookahead(next_slot, payload_lookahead);
        harness
            .chain
            .prepare_beacon_proposer(current_slot)
            .await
            .unwrap();

        // Simulate the scheduled call to fork choice + prepare proposers 500ms before the
        // next slot.
        harness.advance_to_slot_lookahead(next_slot, fork_choice_lookahead);
        harness.chain.recompute_head_at_slot(next_slot).await;
        harness
            .chain
            .prepare_beacon_proposer(current_slot)
            .await
            .unwrap();

        harness.advance_slot();
        harness.chain.per_slot_task().await;
    }

    // Produce block C.
    // Advance state_b so we can get the proposer.
    assert_eq!(state_b.slot(), slot_b);
    let pre_advance_withdrawals = get_expected_withdrawals(&state_b, &harness.chain.spec)
        .unwrap()
        .withdrawals()
        .to_vec();
    complete_state_advance(&mut state_b, None, slot_c, &harness.chain.spec).unwrap();

    let proposer_index = state_b
        .get_beacon_proposer_index(slot_c, &harness.chain.spec)
        .unwrap();
    let randao_reveal = harness
        .sign_randao_reveal(&state_b, proposer_index, slot_c)
        .into();
    let is_gloas = harness
        .chain
        .spec
        .fork_name_at_slot::<E>(slot_c)
        .gloas_enabled();

    let (block_c, block_c_blobs) = if is_gloas {
        let (response, _) = tester
            .client
            .get_validator_blocks_v4::<E>(slot_c, &randao_reveal, None, None, None, None)
            .await
            .unwrap();
        (
            Arc::new(harness.sign_beacon_block(response.data, &state_b)),
            None,
        )
    } else {
        let (unsigned_block_type, _) = tester
            .client
            .get_validator_blocks_v3::<E>(slot_c, &randao_reveal, None, None, None)
            .await
            .unwrap();

        let (unsigned_block_c, block_c_blobs) = match unsigned_block_type.data {
            ProduceBlockV3Response::Full(unsigned_block_contents_c) => {
                unsigned_block_contents_c.deconstruct()
            }
            ProduceBlockV3Response::Blinded(_) => {
                panic!("Should not be a blinded block");
            }
        };
        (
            Arc::new(harness.sign_beacon_block(unsigned_block_c, &state_b)),
            block_c_blobs,
        )
    };

    // Post-Gloas the execution payload is decoupled from the beacon block: the payload hash
    // lives in the execution payload bid, and the payload timestamp is derived from the slot.
    let exec_block_hash = |block: BeaconBlockRef<E>| -> ExecutionBlockHash {
        if is_gloas {
            block
                .body()
                .signed_execution_payload_bid()
                .unwrap()
                .message
                .block_hash
        } else {
            block.execution_payload().unwrap().block_hash()
        }
    };
    let exec_parent_hash = |block: BeaconBlockRef<E>| -> ExecutionBlockHash {
        if is_gloas {
            block
                .body()
                .signed_execution_payload_bid()
                .unwrap()
                .message
                .parent_block_hash
        } else {
            block.execution_payload().unwrap().parent_hash()
        }
    };

    let block_a_exec_hash = exec_block_hash(block_a.0.message());
    let block_b_exec_hash = exec_block_hash(block_b.0.message());

    if is_gloas {
        assert_eq!(
            block_b.0.is_parent_block_full(block_a_exec_hash),
            head_parent_payload_status == PayloadStatus::Full
        );
    }

    if should_re_org {
        // Block C should build on A.
        assert_eq!(block_c.parent_root(), Hash256::from(block_a_root));

        if is_gloas {
            assert_eq!(
                block_c.is_parent_block_full(block_a_exec_hash),
                expected_parent_payload_status == PayloadStatus::Full
            );
        }
    } else {
        // Block C should build on B.
        assert_eq!(block_c.parent_root(), block_b_root);

        if is_gloas {
            assert_eq!(
                block_c.is_parent_block_full(block_b_exec_hash),
                expected_parent_payload_status == PayloadStatus::Full
            );
        }
    }

    // Applying block C should cause it to become head regardless (re-org or continuation).
    let block_root_c = Hash256::from(
        harness
            .process_block_result((block_c.clone(), block_c_blobs))
            .await
            .unwrap(),
    );

    assert_eq!(harness.head_block_root(), block_root_c);

    // Check the fork choice updates that were sent.
    let forkchoice_updates = forkchoice_updates.lock();

    let block_c_timestamp = if is_gloas {
        harness.chain.slot_clock.start_of(slot_c).unwrap().as_secs()
    } else {
        block_c.message().execution_payload().unwrap().timestamp()
    };

    // If we re-orged then no fork choice update for B should have been sent.
    assert_eq!(
        should_re_org,
        !forkchoice_updates.contains_update_for(block_b_exec_hash),
        "{block_b_exec_hash:?}"
    );

    // Check the timing of the first fork choice update with payload attributes for block C.
    let c_parent_block = if should_re_org {
        block_a.0.message()
    } else {
        block_b.0.message()
    };
    let c_parent_hash = if expected_parent_payload_status == PayloadStatus::Full {
        exec_block_hash(c_parent_block)
    } else {
        exec_parent_hash(c_parent_block)
    };
    let first_update = forkchoice_updates
        .first_update_with_payload_attributes(
            c_parent_hash,
            block_c_timestamp,
            is_gloas.then(|| block_c.parent_root()),
            is_gloas.then(|| slot_c.as_u64()),
        )
        .unwrap();
    let payload_attribs = first_update.payload_attributes.as_ref().unwrap();

    // Check that withdrawals from the payload attributes match those computed from the state used
    // by the path that produced the matching fcU.
    let parent_state_advanced = if should_re_org {
        let mut state = state_a.clone();
        complete_state_advance(&mut state, None, slot_c, &harness.chain.spec).unwrap();
        state
    } else {
        state_b.clone()
    };
    let expected_withdrawals = if is_gloas
        && matches!(
            expected_first_update_lookahead,
            ExpectedFirstUpdateLookahead::BlockProduction
        )
        && expected_parent_payload_status == PayloadStatus::Empty
    {
        parent_state_advanced
            .payload_expected_withdrawals()
            .unwrap()
            .to_vec()
    } else {
        get_expected_withdrawals(&parent_state_advanced, &harness.chain.spec)
            .unwrap()
            .withdrawals()
            .to_vec()
    };
    let payload_attribs_withdrawals = payload_attribs.withdrawals().unwrap();
    assert_eq!(expected_withdrawals, *payload_attribs_withdrawals);
    // The validator withdrawal sweep is positional: it scans a rotating window of
    // `max_validators_per_withdrawals_sweep` validators starting at `next_withdrawal_validator_index`.
    // For a given proposal slot that window can legitimately contain no withdrawal-eligible
    // validators (with empty partial/builder withdrawal queues), so an empty withdrawals list is
    // valid. Withdrawal correctness is covered by the equality check above; we only assert the
    // re-org/epoch-boundary withdrawals change when there are withdrawals to compare.
    if !expected_withdrawals.is_empty()
        && (should_re_org
            || expect_withdrawals_change_on_epoch
                && slot_c.epoch(E::slots_per_epoch()) != slot_b.epoch(E::slots_per_epoch()))
    {
        assert_ne!(expected_withdrawals, pre_advance_withdrawals);
    }

    // Check that the `parent_beacon_block_root` of the payload attributes are correct.
    if let Ok(parent_beacon_block_root) = payload_attribs.parent_beacon_block_root() {
        assert_eq!(parent_beacon_block_root, block_c.parent_root());
    }

    let lookahead = slot_clock
        .start_of(slot_c)
        .unwrap()
        .checked_sub(first_update.received_at)
        .unwrap();

    let expected_lookahead = match expected_first_update_lookahead {
        ExpectedFirstUpdateLookahead::Payload => payload_lookahead,
        ExpectedFirstUpdateLookahead::ForkChoice => fork_choice_lookahead,
        ExpectedFirstUpdateLookahead::BlockProduction => Duration::ZERO,
    };
    assert_eq!(
        lookahead,
        expected_lookahead,
        "observed_lookahead={lookahead:?}, expected={expected_lookahead:?}, timestamp={}, prev_randao={:?}",
        payload_attribs.timestamp(),
        payload_attribs.prev_randao(),
    );
}
