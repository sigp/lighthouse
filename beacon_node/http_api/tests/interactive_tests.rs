//! Generic tests that make use of the (newer) `InteractiveApiTester`
use beacon_chain::{
    chain_config::{DisallowedReOrgOffsets, ReOrgThreshold},
    test_utils::{AttestationStrategy, BlockStrategy, SyncCommitteeStrategy},
};
use eth2::types::DepositContractData;
use execution_layer::{ForkchoiceState, PayloadAttributes};
use http_api::test_utils::InteractiveTester;
use parking_lot::Mutex;
use slot_clock::SlotClock;
use state_processing::{
    per_block_processing::get_expected_withdrawals, state_advance::complete_state_advance,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tree_hash::TreeHash;
use types::{
    Address, Epoch, EthSpec, ExecPayload, ExecutionBlockHash, ForkName, FullPayload,
    MainnetEthSpec, ProposerPreparationData, Slot,
};

type E = MainnetEthSpec;

// Test that the deposit_contract endpoint returns the correct chain_id and address.
// Regression test for https://github.com/sigp/lighthouse/issues/2657
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_contract_custom_network() {
    let validator_count = 24;
    let mut spec = E::default_spec();

    // Rinkeby, which we don't use elsewhere.
    spec.deposit_chain_id = 4;
    spec.deposit_network_id = 4;
    // Arbitrary contract address.
    spec.deposit_contract_address = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();

    let tester = InteractiveTester::<E>::new(Some(spec.clone()), validator_count).await;
    let client = &tester.client;

    let result = client.get_config_deposit_contract().await.unwrap().data;

    let expected = DepositContractData {
        address: spec.deposit_contract_address,
        chain_id: spec.deposit_chain_id,
    };

    assert_eq!(result, expected);
}

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
            .or_insert_with(Vec::new)
            .push(update);
    }

    fn contains_update_for(&self, block_hash: ExecutionBlockHash) -> bool {
        self.updates.contains_key(&block_hash)
    }

    /// Find the first fork choice update for `head_block_hash` with payload attributes for a
    /// block proposal at `proposal_timestamp`.
    fn first_update_with_payload_attributes(
        &self,
        head_block_hash: ExecutionBlockHash,
        proposal_timestamp: u64,
    ) -> Option<ForkChoiceUpdateMetadata> {
        self.updates
            .get(&head_block_hash)?
            .iter()
            .find(|update| {
                update
                    .payload_attributes
                    .as_ref()
                    .map_or(false, |payload_attributes| {
                        payload_attributes.timestamp() == proposal_timestamp
                    })
            })
            .cloned()
    }
}

pub struct ReOrgTest {
    head_slot: Slot,
    /// Number of slots between parent block and canonical head.
    parent_distance: u64,
    /// Number of slots between head block and block proposal slot.
    head_distance: u64,
    re_org_threshold: u64,
    max_epochs_since_finalization: u64,
    percent_parent_votes: usize,
    percent_empty_votes: usize,
    percent_head_votes: usize,
    should_re_org: bool,
    misprediction: bool,
    /// Whether to expect withdrawals to change on epoch boundaries.
    expect_withdrawals_change_on_epoch: bool,
    /// Epoch offsets to avoid proposing reorg blocks at.
    disallowed_offsets: Vec<u64>,
}

impl Default for ReOrgTest {
    /// Default config represents a regular easy re-org.
    fn default() -> Self {
        Self {
            head_slot: Slot::new(E::slots_per_epoch() - 2),
            parent_distance: 1,
            head_distance: 1,
            re_org_threshold: 20,
            max_epochs_since_finalization: 2,
            percent_parent_votes: 100,
            percent_empty_votes: 100,
            percent_head_votes: 0,
            should_re_org: true,
            misprediction: false,
            expect_withdrawals_change_on_epoch: false,
            disallowed_offsets: vec![],
        }
    }
}

// Test that the beacon node will try to perform proposer boost re-orgs on late blocks when
// configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_zero_weight() {
    proposer_boost_re_org_test(ReOrgTest::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_epoch_boundary() {
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() - 1),
        should_re_org: false,
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
        percent_empty_votes: 0,
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

// Check that a re-org at a disallowed offset fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_disallowed_offset() {
    let offset = 4;
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() + offset - 1),
        disallowed_offsets: vec![offset],
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

// Check that a re-org at the *only* allowed offset succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_disallowed_offset_exact() {
    let offset = 4;
    let disallowed_offsets = (0..E::slots_per_epoch()).filter(|o| *o != offset).collect();
    proposer_boost_re_org_test(ReOrgTest {
        head_slot: Slot::new(E::slots_per_epoch() + offset - 1),
        disallowed_offsets,
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
        percent_empty_votes: 10,
        percent_head_votes: 10,
        should_re_org: false,
        ..Default::default()
    })
    .await;
}

/// The head block is late but still receives 30% of the committee vote, leading to a misprediction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_weight_misprediction() {
    proposer_boost_re_org_test(ReOrgTest {
        percent_empty_votes: 70,
        percent_head_votes: 30,
        should_re_org: false,
        misprediction: true,
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
pub async fn proposer_boost_re_org_test(
    ReOrgTest {
        head_slot,
        parent_distance,
        head_distance,
        re_org_threshold,
        max_epochs_since_finalization,
        percent_parent_votes,
        percent_empty_votes,
        percent_head_votes,
        should_re_org,
        misprediction,
        expect_withdrawals_change_on_epoch,
        disallowed_offsets,
    }: ReOrgTest,
) {
    assert!(head_slot > 0);

    // Test using Capella so that we simulate conditions as similar to mainnet as possible.
    let mut spec = ForkName::Capella.make_genesis_spec(E::default_spec());
    spec.terminal_total_difficulty = 1.into();

    // Ensure there are enough validators to have `attesters_per_slot`.
    let attesters_per_slot = 10;
    let validator_count = E::slots_per_epoch() as usize * attesters_per_slot;
    let all_validators = (0..validator_count).collect::<Vec<usize>>();
    let num_initial = head_slot.as_u64().checked_sub(parent_distance + 1).unwrap();

    // Check that the required vote percentages can be satisfied exactly using `attesters_per_slot`.
    assert_eq!(100 % attesters_per_slot, 0);
    let percent_per_attester = 100 / attesters_per_slot;
    assert_eq!(percent_parent_votes % percent_per_attester, 0);
    assert_eq!(percent_empty_votes % percent_per_attester, 0);
    assert_eq!(percent_head_votes % percent_per_attester, 0);
    let num_parent_votes = Some(attesters_per_slot * percent_parent_votes / 100);
    let num_empty_votes = Some(attesters_per_slot * percent_empty_votes / 100);
    let num_head_votes = Some(attesters_per_slot * percent_head_votes / 100);

    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(spec),
        validator_count,
        None,
        Some(Box::new(move |builder| {
            builder
                .proposer_re_org_threshold(Some(ReOrgThreshold(re_org_threshold)))
                .proposer_re_org_max_epochs_since_finalization(Epoch::new(
                    max_epochs_since_finalization,
                ))
                .proposer_re_org_disallowed_offsets(
                    DisallowedReOrgOffsets::new::<E>(disallowed_offsets).unwrap(),
                )
        })),
    )
    .await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();
    let execution_ctx = mock_el.server.ctx.clone();
    let slot_clock = &harness.chain.slot_clock;

    // Move to terminal block.
    mock_el.server.all_payloads_valid();
    execution_ctx
        .execution_block_generator
        .write()
        .move_to_terminal_block()
        .unwrap();

    // Send proposer preparation data for all validators.
    let proposer_preparation_data = all_validators
        .iter()
        .map(|i| ProposerPreparationData {
            validator_index: *i as u64,
            fee_recipient: Address::from_low_u64_be(*i as u64),
        })
        .collect::<Vec<_>>();
    harness
        .chain
        .execution_layer
        .as_ref()
        .unwrap()
        .update_proposer_preparation(
            head_slot.epoch(E::slots_per_epoch()) + 1,
            &proposer_preparation_data,
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
    let (block_a_root, block_a, state_a) = harness
        .add_block_at_slot(slot_a, harness.get_current_state())
        .await
        .unwrap();

    // Attest to block A during slot A.
    let (block_a_parent_votes, _) = harness.make_attestations_with_limit(
        &all_validators,
        &state_a,
        state_a.canonical_root(),
        block_a_root,
        slot_a,
        num_parent_votes,
    );
    harness.process_attestations(block_a_parent_votes);

    // Attest to block A during slot B.
    for _ in 0..parent_distance {
        harness.advance_slot();
    }
    let (block_a_empty_votes, block_a_attesters) = harness.make_attestations_with_limit(
        &all_validators,
        &state_a,
        state_a.canonical_root(),
        block_a_root,
        slot_b,
        num_empty_votes,
    );
    harness.process_attestations(block_a_empty_votes);

    let remaining_attesters = all_validators
        .iter()
        .copied()
        .filter(|index| !block_a_attesters.contains(index))
        .collect::<Vec<_>>();

    // Produce block B and process it halfway through the slot.
    let (block_b, mut state_b) = harness.make_block(state_a.clone(), slot_b).await;
    let block_b_root = block_b.canonical_root();

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

    // Add attestations to block B.
    let (block_b_head_votes, _) = harness.make_attestations_with_limit(
        &remaining_attesters,
        &state_b,
        state_b.canonical_root(),
        block_b_root.into(),
        slot_b,
        num_head_votes,
    );
    harness.process_attestations(block_b_head_votes);

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
        .to_vec();
    complete_state_advance(&mut state_b, None, slot_c, &harness.chain.spec).unwrap();

    let proposer_index = state_b
        .get_beacon_proposer_index(slot_c, &harness.chain.spec)
        .unwrap();
    let randao_reveal = harness
        .sign_randao_reveal(&state_b, proposer_index, slot_c)
        .into();
    let unsigned_block_c = tester
        .client
        .get_validator_blocks(slot_c, &randao_reveal, None)
        .await
        .unwrap()
        .data;
    let block_c = harness.sign_beacon_block(unsigned_block_c, &state_b);

    if should_re_org {
        // Block C should build on A.
        assert_eq!(block_c.parent_root(), block_a_root.into());
    } else {
        // Block C should build on B.
        assert_eq!(block_c.parent_root(), block_b_root);
    }

    // Applying block C should cause it to become head regardless (re-org or continuation).
    let block_root_c = harness
        .process_block_result(block_c.clone())
        .await
        .unwrap()
        .into();
    assert_eq!(harness.head_block_root(), block_root_c);

    // Check the fork choice updates that were sent.
    let forkchoice_updates = forkchoice_updates.lock();
    let block_a_exec_hash = block_a.message().execution_payload().unwrap().block_hash();
    let block_b_exec_hash = block_b.message().execution_payload().unwrap().block_hash();

    let block_c_timestamp = block_c.message().execution_payload().unwrap().timestamp();

    // If we re-orged then no fork choice update for B should have been sent.
    assert_eq!(
        should_re_org,
        !forkchoice_updates.contains_update_for(block_b_exec_hash),
        "{block_b_exec_hash:?}"
    );

    // Check the timing of the first fork choice update with payload attributes for block C.
    let c_parent_hash = if should_re_org {
        block_a_exec_hash
    } else {
        block_b_exec_hash
    };
    let first_update = forkchoice_updates
        .first_update_with_payload_attributes(c_parent_hash, block_c_timestamp)
        .unwrap();
    let payload_attribs = first_update.payload_attributes.as_ref().unwrap();

    // Check that withdrawals from the payload attributes match those computed from the parent's
    // advanced state.
    let expected_withdrawals = if should_re_org {
        let mut state_a_advanced = state_a.clone();
        complete_state_advance(&mut state_a_advanced, None, slot_c, &harness.chain.spec).unwrap();
        get_expected_withdrawals(&state_a_advanced, &harness.chain.spec)
    } else {
        get_expected_withdrawals(&state_b, &harness.chain.spec)
    }
    .unwrap()
    .to_vec();
    let payload_attribs_withdrawals = payload_attribs.withdrawals().unwrap();
    assert_eq!(expected_withdrawals, *payload_attribs_withdrawals);
    assert!(!expected_withdrawals.is_empty());

    if should_re_org
        || expect_withdrawals_change_on_epoch
            && slot_c.epoch(E::slots_per_epoch()) != slot_b.epoch(E::slots_per_epoch())
    {
        assert_ne!(expected_withdrawals, pre_advance_withdrawals);
    }

    let lookahead = slot_clock
        .start_of(slot_c)
        .unwrap()
        .checked_sub(first_update.received_at)
        .unwrap();

    if !misprediction {
        assert_eq!(
            lookahead,
            payload_lookahead,
            "lookahead={lookahead:?}, timestamp={}, prev_randao={:?}",
            payload_attribs.timestamp(),
            payload_attribs.prev_randao(),
        );
    } else {
        // On a misprediction we issue the first fcU 500ms before creating a block!
        assert_eq!(
            lookahead,
            fork_choice_lookahead,
            "timestamp={}, prev_randao={:?}",
            payload_attribs.timestamp(),
            payload_attribs.prev_randao(),
        );
    }
}

// Test that running fork choice before proposing results in selection of the correct head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn fork_choice_before_proposal() {
    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let all_validators = (0..validator_count).collect::<Vec<_>>();
    let num_initial: u64 = 31;

    let tester = InteractiveTester::<E>::new(None, validator_count).await;
    let harness = &tester.harness;

    // Create some chain depth.
    harness.advance_slot();
    harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // We set up the following block graph, where B is a block that is temporarily orphaned by C,
    // but is then reinstated and built upon by D.
    //
    // A | B | - | D |
    // ^ | - | C |
    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;
    let slot_c = slot_a + 2;
    let slot_d = slot_a + 3;

    let state_a = harness.get_current_state();
    let (block_b, state_b) = harness.make_block(state_a.clone(), slot_b).await;
    let block_root_b = harness
        .process_block(slot_b, block_b.canonical_root(), block_b)
        .await
        .unwrap();

    // Create attestations to B but keep them in reserve until after C has been processed.
    let attestations_b = harness.make_attestations(
        &all_validators,
        &state_b,
        state_b.tree_hash_root(),
        block_root_b,
        slot_b,
    );

    let (block_c, state_c) = harness.make_block(state_a, slot_c).await;
    let block_root_c = harness
        .process_block(slot_c, block_c.canonical_root(), block_c.clone())
        .await
        .unwrap();

    // Create attestations to C from a small number of validators and process them immediately.
    let attestations_c = harness.make_attestations(
        &all_validators[..validator_count / 2],
        &state_c,
        state_c.tree_hash_root(),
        block_root_c,
        slot_c,
    );
    harness.process_attestations(attestations_c);

    // Apply the attestations to B, but don't re-run fork choice.
    harness.process_attestations(attestations_b);

    // Due to proposer boost, the head should be C during slot C.
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_block_root(),
        block_root_c.into()
    );

    // Ensure that building a block via the HTTP API re-runs fork choice and builds block D upon B.
    // Manually prod the per-slot task, because the slot timer doesn't run in the background in
    // these tests.
    harness.advance_slot();
    harness.chain.per_slot_task().await;

    let proposer_index = state_b
        .get_beacon_proposer_index(slot_d, &harness.chain.spec)
        .unwrap();
    let randao_reveal = harness
        .sign_randao_reveal(&state_b, proposer_index, slot_d)
        .into();
    let block_d = tester
        .client
        .get_validator_blocks::<E, FullPayload<E>>(slot_d, &randao_reveal, None)
        .await
        .unwrap()
        .data;

    // Head is now B.
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_block_root(),
        block_root_b.into()
    );
    // D's parent is B.
    assert_eq!(block_d.parent_root(), block_root_b.into());
}
