#![cfg(not(debug_assertions))]

use beacon_chain::ChainConfig;
use beacon_chain::light_client_epoch_backfill::backfill_light_client_epoch_data;
use beacon_chain::test_utils::{
    BeaconChainHarness, EphemeralHarnessType, SyncCommitteeStrategy, test_spec,
};
use store::metadata::{LC_EPOCH_BACKFILL_PROGRESS_KEY, LightClientEpochBackfillProgress};
use types::{EthSpec, MinimalEthSpec, Slot};

const VALIDATOR_COUNT: usize = 32;

type TestHarness = BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>>;

fn test_chain_spec() -> std::sync::Arc<types::ChainSpec> {
    std::sync::Arc::new(test_spec::<MinimalEthSpec>())
}

async fn build_harness(num_periods: u64) -> TestHarness {
    let spec = test_chain_spec();

    let slots_per_period =
        MinimalEthSpec::slots_per_epoch() * u64::from(spec.epochs_per_sync_committee_period);
    let total_slots = slots_per_period * num_periods;

    let all_validators = (0..VALIDATOR_COUNT).collect::<Vec<_>>();
    let slots: Vec<Slot> = (1..total_slots).map(Slot::new).collect();

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec)
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .chain_config(ChainConfig {
            archive: true,
            ..ChainConfig::default()
        })
        .mock_execution_layer()
        .build();

    let genesis_state = harness.get_current_state();

    harness
        .add_attested_blocks_at_slots_with_sync(
            genesis_state,
            &slots,
            &all_validators,
            SyncCommitteeStrategy::AllValidators,
        )
        .await;

    harness
}

fn backfill_progress(harness: &TestHarness) -> Option<LightClientEpochBackfillProgress> {
    harness
        .chain
        .store
        .get_item::<LightClientEpochBackfillProgress>(&LC_EPOCH_BACKFILL_PROGRESS_KEY)
        .unwrap()
}

#[tokio::test]
async fn lc_epoch_backfill_matches_live_capture() {
    let harness = build_harness(3).await;

    let finalized_period = harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .finalized_checkpoint()
        .epoch
        .sync_committee_period(&harness.spec)
        .unwrap();

    let updates_before = harness
        .chain
        .get_light_client_updates(0, finalized_period + 1)
        .unwrap();

    assert!(
        updates_before.is_empty(),
        "the test harness should not have populated the light-client cache"
    );

    let clean = backfill_light_client_epoch_data(&harness.chain).unwrap();
    assert!(clean);

    let updates_after = harness
        .chain
        .get_light_client_updates(0, finalized_period + 1)
        .unwrap();

    assert!(
        !updates_after.is_empty(),
        "backfill should produce at least one light-client update"
    );
}

#[tokio::test]
async fn lc_epoch_backfill_is_resumable() {
    let harness = build_harness(3).await;

    let clean_first = backfill_light_client_epoch_data(&harness.chain).unwrap();
    assert!(clean_first);

    let progress_after_first = backfill_progress(&harness).expect("progress should be persisted");

    let clean_second = backfill_light_client_epoch_data(&harness.chain).unwrap();
    assert!(clean_second);

    let progress_after_second =
        backfill_progress(&harness).expect("progress should remain present");

    assert_eq!(progress_after_first, progress_after_second);
}

#[tokio::test]
async fn lc_epoch_backfill_stops_on_missing_block() {
    let harness = build_harness(2).await;

    let target_slot = Slot::new(MinimalEthSpec::slots_per_epoch() * 2);
    let block_root = harness
        .chain
        .block_root_at_slot(target_slot, beacon_chain::WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();

    let affected_period = target_slot
        .epoch(MinimalEthSpec::slots_per_epoch())
        .sync_committee_period(&harness.spec)
        .unwrap();

    harness.chain.store.delete_block(&block_root).unwrap();

    let clean = backfill_light_client_epoch_data(&harness.chain).unwrap();
    assert!(!clean);

    let progress = backfill_progress(&harness);
    assert_ne!(progress.map(|p| p.0), Some(affected_period));
}

#[tokio::test]
async fn lc_epoch_backfill_handles_skipped_slots() {
    let spec = test_chain_spec();
    let slots_per_period =
        MinimalEthSpec::slots_per_epoch() * u64::from(spec.epochs_per_sync_committee_period);
    let total_slots = slots_per_period * 3;

    let all_validators = (0..VALIDATOR_COUNT).collect::<Vec<_>>();
    let slots: Vec<Slot> = (1..total_slots)
        .filter(|slot| slot % 3 != 0)
        .map(Slot::new)
        .collect();

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec)
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .chain_config(ChainConfig {
            archive: true,
            ..ChainConfig::default()
        })
        .mock_execution_layer()
        .build();

    let genesis_state = harness.get_current_state();

    harness
        .add_attested_blocks_at_slots_with_sync(
            genesis_state,
            &slots,
            &all_validators,
            SyncCommitteeStrategy::AllValidators,
        )
        .await;

    let clean = backfill_light_client_epoch_data(&harness.chain).unwrap();
    assert!(clean);

    let progress = backfill_progress(&harness).expect("progress should be present");

    let updates = harness
        .chain
        .get_light_client_updates(0, progress.0 + 1)
        .unwrap();
    assert!(
        !updates.is_empty(),
        "backfill should produce at least one update despite skipped slots"
    );
}
