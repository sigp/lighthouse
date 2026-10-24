//! Regression tests for https://github.com/sigp/lighthouse/issues/9530.
//!
//! When the head is many epochs behind the wall clock, validator API handlers that need a
//! current/next-epoch state must not replay every empty epoch from the head on each new epoch.
//! These tests jump the clock, then advance epoch-by-epoch and assert that `process_epoch` work
//! for each new epoch stays roughly one epoch — not O(staleness).
//!
//! Expected to **fail** on `unstable` / `ef55e2fbf` and **pass** once the advanced-head-state
//! fix is applied.

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    LightClientStrategy, SyncCommitteeStrategy, test_spec,
};
use eth2::BeaconNodeHttpClient;
use eth2::types::{ProduceBlockV3Response, StateId};
use futures::future::join_all;
use http_api::test_utils::InteractiveTester;
use state_processing::state_advance::partial_state_advance;
use std::time::Instant;
use types::{Epoch, EthSpec, Hash256, Slot, Spec};

type E = Spec;

/// Sample count for the global `beacon_state_processing_process_epoch` histogram.
fn process_epoch_sample_count() -> u64 {
    metrics::gather()
        .iter()
        .find(|mf| mf.get_name() == "beacon_state_processing_process_epoch")
        .map(|mf| {
            mf.get_metric()
                .iter()
                .map(|m| m.get_histogram().get_sample_count())
                .sum()
        })
        .unwrap_or(0)
}

struct StaleHeadHarness {
    tester: InteractiveTester<E>,
    validator_count: usize,
    slots_per_epoch: u64,
    stale_epochs: u64,
    head_block_root: Hash256,
    /// Wall-clock slot after the initial stale jump (head + stale_epochs).
    future_slot: Slot,
}

impl StaleHeadHarness {
    async fn setup(stale_epochs: u64) -> Self {
        let spec = test_spec::<E>();
        // 64 validators so Gloas genesis (balance-weighted proposer selection) succeeds.
        let validator_count = 64;
        let slots_per_epoch = E::slots_per_epoch();

        let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;
        let harness = &tester.harness;
        let mock_el = harness.mock_execution_layer.as_ref().unwrap();
        mock_el.server.all_payloads_valid();

        let num_slots = 3 * slots_per_epoch;
        harness.advance_slot();
        harness
            .extend_chain_with_sync(
                num_slots as usize,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
                SyncCommitteeStrategy::NoValidators,
                LightClientStrategy::Disabled,
            )
            .await;

        let head_slot = harness.head_slot();
        let head_epoch = head_slot.epoch(slots_per_epoch);
        assert_eq!(head_epoch, Epoch::new(3));

        let future_slot = head_slot + Slot::new(stale_epochs * slots_per_epoch);
        harness.set_current_slot(future_slot);

        let current_epoch = harness.chain.epoch().unwrap();
        assert_eq!(current_epoch, head_epoch + stale_epochs);
        assert_eq!(harness.chain.slot().unwrap(), future_slot);

        let head_block_root = harness.chain.canonical_head.cached_head().head_block_root();

        Self {
            tester,
            validator_count,
            slots_per_epoch,
            stale_epochs,
            head_block_root,
            future_slot,
        }
    }

    fn harness(&self) -> &BeaconChainHarness<EphemeralHarnessType<E>> {
        &self.tester.harness
    }

    fn client(&self) -> &BeaconNodeHttpClient {
        &self.tester.client
    }

    fn advance_one_epoch(&self) {
        let next = self.harness().chain.slot().unwrap() + Slot::new(self.slots_per_epoch);
        self.harness().set_current_slot(next);
    }
}

/// Assert `delta` is far below a full stale-head replay of `baseline` epochs of work.
fn assert_incremental(delta: u64, baseline: u64, label: &str) {
    assert!(
        delta > 0,
        "{label}: expected some epoch processing for a new epoch, got 0"
    );
    assert!(
        delta < baseline.saturating_add(1) / 2,
        "{label}: expected ~1 epoch of work after prior advance, got delta={delta} \
         (baseline full-replay delta={baseline}). Cost still grows with staleness."
    );
    // Hard cap: never more than a few epochs of work once an advanced state exists.
    assert!(
        delta <= 4,
        "{label}: incremental advance should be a handful of process_epoch samples, got {delta}"
    );
}

/// Attestation data: after a cold stale jump, each further epoch should cost ~1 process_epoch
/// of work, not another full replay from the head.
#[tokio::test(flavor = "multi_thread")]
async fn attestation_data_incremental_with_stale_head() {
    let ctx = StaleHeadHarness::setup(12).await;
    let client = ctx.client();
    let slot0 = ctx.future_slot;

    let before = process_epoch_sample_count();
    let first = client
        .get_validator_attestation_data(slot0, 0)
        .await
        .unwrap()
        .data;
    let cold_delta = process_epoch_sample_count().saturating_sub(before);
    assert!(
        cold_delta >= ctx.stale_epochs / 2,
        "cold attestation_data should process most empty epochs, got delta={cold_delta}"
    );
    assert_eq!(first.beacon_block_root, ctx.head_block_root);
    assert_eq!(first.slot, slot0);

    // Same-slot repeat should add little/no epoch work once an advanced state exists.
    let before_repeat = process_epoch_sample_count();
    let repeat = client
        .get_validator_attestation_data(slot0, 0)
        .await
        .unwrap()
        .data;
    let repeat_delta = process_epoch_sample_count().saturating_sub(before_repeat);
    assert_eq!(repeat, first);
    assert!(
        repeat_delta <= 1,
        "repeat attestation_data should not replay empty epochs (delta={repeat_delta})"
    );

    ctx.advance_one_epoch();
    let slot1 = ctx.harness().chain.slot().unwrap();
    let before_next = process_epoch_sample_count();
    let second = client
        .get_validator_attestation_data(slot1, 0)
        .await
        .unwrap()
        .data;
    let next_delta = process_epoch_sample_count().saturating_sub(before_next);
    assert_incremental(next_delta, cold_delta, "attestation_data +1 epoch");
    assert_eq!(second.slot, slot1);
    assert_eq!(second.beacon_block_root, ctx.head_block_root);

    ctx.advance_one_epoch();
    let slot2 = ctx.harness().chain.slot().unwrap();
    let before_third = process_epoch_sample_count();
    let third = client
        .get_validator_attestation_data(slot2, 0)
        .await
        .unwrap()
        .data;
    let third_delta = process_epoch_sample_count().saturating_sub(before_third);
    assert_incremental(third_delta, cold_delta, "attestation_data +2 epochs");
    assert_eq!(third.slot, slot2);

    // Cold concurrent callers for a brand-new epoch must single-flight.
    ctx.advance_one_epoch();
    let cold_slot = ctx.harness().chain.slot().unwrap();
    const CONCURRENT: usize = 4;
    let before_cold = process_epoch_sample_count();
    let results = join_all((0..CONCURRENT).map(|_| {
        let client = client.clone();
        async move {
            client
                .get_validator_attestation_data(cold_slot, 0)
                .await
                .unwrap()
                .data
        }
    }))
    .await;
    let cold_conc = process_epoch_sample_count().saturating_sub(before_cold);
    assert_incremental(
        cold_conc,
        cold_delta,
        "attestation_data concurrent new epoch",
    );
    for r in &results {
        assert_eq!(r, &results[0]);
    }

    // New head must be reflected.
    let state = ctx.harness().get_current_state();
    let validators: Vec<usize> = (0..ctx.validator_count).collect();
    ctx.harness()
        .add_attested_block_at_slot(cold_slot, state, &validators)
        .await
        .unwrap();
    let new_head = ctx
        .harness()
        .chain
        .canonical_head
        .cached_head()
        .head_block_root();
    assert_ne!(new_head, ctx.head_block_root);
    let after_block = client
        .get_validator_attestation_data(cold_slot, 0)
        .await
        .unwrap()
        .data;
    assert_eq!(after_block.beacon_block_root, new_head);
}

/// Next-epoch proposer duties: incremental cost stays flat as the clock advances.
#[tokio::test(flavor = "multi_thread")]
async fn proposer_duties_incremental_with_stale_head() {
    let spec = test_spec::<E>();
    if !spec.is_fulu_scheduled() {
        // Pre-Fulu next-epoch duties are intentionally uncached / undecided mid-epoch.
        return;
    }

    let ctx = StaleHeadHarness::setup(12).await;
    let client = ctx.client();

    let next_epoch = ctx.harness().chain.epoch().unwrap() + 1;
    let before = process_epoch_sample_count();
    let first = client
        .get_validator_duties_proposer_v2(next_epoch)
        .await
        .unwrap();
    let cold_delta = process_epoch_sample_count().saturating_sub(before);
    assert!(
        cold_delta >= ctx.stale_epochs / 2,
        "cold next-epoch proposer duties should process most empty epochs, got delta={cold_delta}"
    );
    assert_eq!(first.data.len() as u64, ctx.slots_per_epoch);

    let before_repeat = process_epoch_sample_count();
    let repeat = client
        .get_validator_duties_proposer_v2(next_epoch)
        .await
        .unwrap();
    let repeat_delta = process_epoch_sample_count().saturating_sub(before_repeat);
    assert_eq!(repeat, first);
    assert_eq!(
        repeat_delta, 0,
        "repeat proposer duties should hit cache (delta={repeat_delta})"
    );

    ctx.advance_one_epoch();
    let next_epoch = ctx.harness().chain.epoch().unwrap() + 1;
    let before_next = process_epoch_sample_count();
    let second = client
        .get_validator_duties_proposer_v2(next_epoch)
        .await
        .unwrap();
    let next_delta = process_epoch_sample_count().saturating_sub(before_next);
    assert_incremental(next_delta, cold_delta, "proposer_duties +1 epoch");
    assert_eq!(second.data.len() as u64, ctx.slots_per_epoch);

    ctx.advance_one_epoch();
    let next_epoch = ctx.harness().chain.epoch().unwrap() + 1;
    let before_third = process_epoch_sample_count();
    let _third = client
        .get_validator_duties_proposer_v2(next_epoch)
        .await
        .unwrap();
    let third_delta = process_epoch_sample_count().saturating_sub(before_third);
    assert_incremental(third_delta, cold_delta, "proposer_duties +2 epochs");
}

/// Attester duties for the current epoch: same incremental property via the shuffling path.
#[tokio::test(flavor = "multi_thread")]
async fn attester_duties_incremental_with_stale_head() {
    let ctx = StaleHeadHarness::setup(12).await;
    let client = ctx.client();
    let indices: Vec<u64> = (0..ctx.validator_count as u64).collect();

    let epoch0 = ctx.harness().chain.epoch().unwrap();
    let before = process_epoch_sample_count();
    let first = client
        .post_validator_duties_attester(epoch0, &indices)
        .await
        .unwrap();
    let cold_delta = process_epoch_sample_count().saturating_sub(before);
    assert!(
        cold_delta >= ctx.stale_epochs / 2,
        "cold attester duties should process most empty epochs, got delta={cold_delta}"
    );
    assert!(!first.data.is_empty());

    let before_repeat = process_epoch_sample_count();
    let repeat = client
        .post_validator_duties_attester(epoch0, &indices)
        .await
        .unwrap();
    let repeat_delta = process_epoch_sample_count().saturating_sub(before_repeat);
    assert_eq!(repeat.data, first.data);
    assert!(
        repeat_delta <= 1,
        "repeat attester duties should reuse shuffling / advanced state (delta={repeat_delta})"
    );

    ctx.advance_one_epoch();
    let epoch1 = ctx.harness().chain.epoch().unwrap();
    let before_next = process_epoch_sample_count();
    let second = client
        .post_validator_duties_attester(epoch1, &indices)
        .await
        .unwrap();
    let next_delta = process_epoch_sample_count().saturating_sub(before_next);
    assert_incremental(next_delta, cold_delta, "attester_duties +1 epoch");
    assert!(!second.data.is_empty());

    ctx.advance_one_epoch();
    let epoch2 = ctx.harness().chain.epoch().unwrap();
    let before_third = process_epoch_sample_count();
    let _third = client
        .post_validator_duties_attester(epoch2, &indices)
        .await
        .unwrap();
    let third_delta = process_epoch_sample_count().saturating_sub(before_third);
    assert_incremental(third_delta, cold_delta, "attester_duties +2 epochs");
}

/// Complete empty-slot advances for block production must stay incremental under a stale head.
///
/// Measures `head_state_completely_advanced_to` directly (the shared mechanism used by
/// `load_state_for_block_production`), then sanity-checks one HTTP produce for parent root.
#[tokio::test(flavor = "multi_thread")]
async fn block_production_incremental_with_stale_head() {
    let ctx = StaleHeadHarness::setup(8).await;
    let client = ctx.client();
    let harness = ctx.harness();
    let chain = harness.chain.clone();

    let slot0 = ctx.future_slot;
    let before = process_epoch_sample_count();
    let (root0, state0) = chain.head_state_completely_advanced_to(slot0).unwrap();
    let cold_delta = process_epoch_sample_count().saturating_sub(before);
    assert!(
        cold_delta >= ctx.stale_epochs / 2,
        "cold complete advance should process most empty epochs, got delta={cold_delta}"
    );
    assert_eq!(state0.slot(), slot0);
    assert_ne!(root0, Hash256::ZERO);

    ctx.advance_one_epoch();
    let slot1 = chain.slot().unwrap();
    let before_next = process_epoch_sample_count();
    let (_root1, state1) = chain.head_state_completely_advanced_to(slot1).unwrap();
    let next_delta = process_epoch_sample_count().saturating_sub(before_next);
    assert_incremental(next_delta, cold_delta, "complete advance +1 epoch");
    assert_eq!(state1.slot(), slot1);

    ctx.advance_one_epoch();
    let slot2 = chain.slot().unwrap();
    let before_third = process_epoch_sample_count();
    let (_root2, state2) = chain.head_state_completely_advanced_to(slot2).unwrap();
    let third_delta = process_epoch_sample_count().saturating_sub(before_third);
    assert_incremental(third_delta, cold_delta, "complete advance +2 epochs");
    assert_eq!(state2.slot(), slot2);

    // HTTP produce at the wall-clock slot should build on the stale head.
    let epoch = slot2.epoch(E::slots_per_epoch());
    let duties = client
        .get_validator_duties_proposer_v2(epoch)
        .await
        .unwrap();
    let duty = duties
        .data
        .iter()
        .find(|d| d.slot == slot2)
        .expect("proposer duty for slot");
    let proposer_index = duty.validator_index as usize;
    let head_state = harness.get_current_state();
    let randao = harness
        .sign_randao_reveal(&head_state, proposer_index, slot2)
        .into();
    let (block_type, _) = client
        .get_validator_blocks_v3::<E>(slot2, &randao, None, None, None)
        .await
        .unwrap();
    match block_type.data {
        ProduceBlockV3Response::Full(contents) => {
            let (block, _) = contents.deconstruct();
            assert_eq!(block.slot(), slot2);
            assert_eq!(block.parent_root(), ctx.head_block_root);
        }
        ProduceBlockV3Response::Blinded(_) => panic!("expected full block"),
    }
}

/// Sync duties stay on the head committees for typical outage lengths (same sync period).
#[tokio::test(flavor = "multi_thread")]
async fn sync_duties_cheap_with_stale_head() {
    let ctx = StaleHeadHarness::setup(12).await;
    let indices: Vec<u64> = (0..ctx.validator_count as u64).collect();
    let epoch = ctx.harness().chain.epoch().unwrap();

    let before = process_epoch_sample_count();
    let start = Instant::now();
    let _duties = ctx
        .client()
        .post_validator_duties_sync(epoch, &indices)
        .await
        .unwrap();
    let elapsed = start.elapsed();
    let delta = process_epoch_sample_count().saturating_sub(before);

    assert_eq!(
        delta, 0,
        "sync duties within the same sync period must not advance empty epochs (delta={delta})"
    );
    assert!(
        elapsed.as_millis() < 500,
        "sync duties should be cheap with a stale head, took {elapsed:?}"
    );
}

/// `states/{slot}/validators` for a skipped slot at the wall clock (past the head block) is cheap:
/// `state_root_at_slot` returns the head state root without empty-epoch processing. Charon's
/// `states/head/validators` fallback is likewise a clone.
#[tokio::test(flavor = "multi_thread")]
async fn states_validators_past_head_cheap_with_stale_head() {
    let ctx = StaleHeadHarness::setup(12).await;
    let past_head_slot = ctx.future_slot;
    assert!(past_head_slot > ctx.harness().head_slot());

    let before = process_epoch_sample_count();
    let start = Instant::now();
    let result = ctx
        .client()
        .post_beacon_states_validators(StateId::Slot(past_head_slot), None, None)
        .await
        .unwrap()
        .expect("skipped slot at/before wall clock resolves via head state root");
    let elapsed = start.elapsed();
    let delta = process_epoch_sample_count().saturating_sub(before);

    assert_eq!(
        delta, 0,
        "states/{{slot}}/validators for a skip slot past the head must not process epochs \
         (delta={delta})"
    );
    assert!(
        elapsed.as_millis() < 500,
        "skip-slot states/validators should be cheap, took {elapsed:?}"
    );
    assert_eq!(result.data.len(), ctx.validator_count);

    // Head fallback used by Charon is a cheap clone.
    let before_head = process_epoch_sample_count();
    let head = ctx
        .client()
        .post_beacon_states_validators(StateId::Head, None, None)
        .await
        .unwrap()
        .expect("head validators");
    let head_delta = process_epoch_sample_count().saturating_sub(before_head);
    assert_eq!(head_delta, 0);
    assert_eq!(head.data.len(), ctx.validator_count);
}

/// Sanity: without going through the HTTP cache layers, advancing from the head for N epochs
/// really does cost ~N process_epoch samples (documents the metric used above).
#[tokio::test(flavor = "multi_thread")]
async fn process_epoch_count_scales_with_manual_advance() {
    let ctx = StaleHeadHarness::setup(6).await;
    let harness = ctx.harness();
    let mut state = harness.get_current_state();
    let state_root = harness.chain.canonical_head.cached_head().head_state_root();
    let target = ctx.future_slot;

    let before = process_epoch_sample_count();
    partial_state_advance(
        &mut state,
        Some(state_root),
        target,
        harness.chain.builder_onboarding_cache.as_deref(),
        &harness.spec,
    )
    .unwrap();
    let delta = process_epoch_sample_count().saturating_sub(before);
    assert_eq!(state.slot(), target);
    assert!(
        delta >= ctx.stale_epochs.saturating_sub(1),
        "manual advance over {stale} stale epochs should record ~that many process_epoch samples, got {delta}",
        stale = ctx.stale_epochs
    );
}
