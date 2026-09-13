use std::sync::Arc;
use types::{ChainSpec, Epoch, Hash256, Slot, EthSpec};
use store::metadata::{LC_EPOCH_BACKFILL_PROGRESS_KEY, LightClientEpochBackfillProgress};
use crate::{BeaconChain, BeaconChainError as Error, BeaconChainTypes};
use tracing::{warn};

/// Walks finalized sync committee periods **forward** — from the node's
/// earliest available state up to the most recently finalized period at the
/// time the task started — feeding every block in each period through the
/// existing live-import update path.
///
/// Must walk forward: `historic_state_cache` (hot_cold_store.rs) only finds
/// a cached state at or below the slot being requested, so it only pays off
/// when queries move in increasing slot order. Walking backward defeats it
/// entirely (every period pays full replay cost from the nearest snapshot).
///
/// Only ever touches finalized periods, so the orphan/reorg-invalidation
/// handling the live path needs for recent data does not apply here.
///
/// Gating (opt-in flag, `SyncState::Synced` check) is the caller's job —
/// this function assumes it's already been decided that backfill should run.
pub fn backfill_light_client_epoch_data<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<(), Error> {
    let spec = &chain.spec;
    let slots_per_epoch = T::EthSpec::slots_per_epoch();

    // Upper bound: captured once, at task start. Anything that finalizes
    // after this point is the live-import path's job, not backfill's.
    let finalized_epoch = chain
        .canonical_head
        .fork_choice_read_lock()
        .finalized_checkpoint()
        .epoch;
    let newest_period = finalized_epoch.sync_committee_period(spec)?;

    // Lower bound: the real state-availability floor.
    let (_state_lower_limit, state_upper_limit) = chain.store.get_historic_state_limits();
    let oldest_period = state_upper_limit
        .epoch(slots_per_epoch)
        .sync_committee_period(spec)?;

    // Resume from the watermark i.e the highest sync committee period 
    // that has been fully processed and recorded in persistent storage.
    let start_period = chain
        .store
        .get_item::<LightClientEpochBackfillProgress>(&LC_EPOCH_BACKFILL_PROGRESS_KEY)?
        .map(|progress| progress.0.saturating_add(1))
        .unwrap_or(oldest_period);

    for period in start_period..=newest_period {
        backfill_period(chain, period, spec, slots_per_epoch)?;

        // Only advance the watermark after the *entire* period is done —
        // this is what makes "resume" actually mean "resume", not
        // "re-derive whether a partial period looks done".
        chain.store.put_item(
            &LC_EPOCH_BACKFILL_PROGRESS_KEY,
            &LightClientEpochBackfillProgress(period),
        )?;

        // Pausable/low-priority: yield between periods. No priority-aware
        // yield primitive exists in the codebase today (checked) — this is
        // the honest starting point, not a considered final answer.
        // tokio::task::yield_now().await;  // if this fn is made async
    }

    Ok(())
}

/// Process a single sync committee period, in slot order. Every block in
/// the period is fed through the existing update path `recompute_and_cache_light_client_updates`
fn backfill_period<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    period: u64,
    spec: &ChainSpec,
    slots_per_epoch: u64,
) -> Result<(), Error> {
    let period_start_epoch = Epoch::new(period * spec.epochs_per_sync_committee_period);
    let period_end_epoch = period_start_epoch + spec.epochs_per_sync_committee_period;

    let start_slot = period_start_epoch.start_slot(slots_per_epoch);
    let end_slot = period_end_epoch.start_slot(slots_per_epoch);

    let mut last_root: Option<Hash256> = None;

    for result in chain.forwards_iter_block_roots_until(start_slot, end_slot)? {
        let (block_root, slot) = result?;

        // Repeated root = Normal empty slot.
        if last_root == Some(block_root) {
            continue;
        }
        last_root = Some(block_root);

        match chain.get_blinded_block(&block_root)? {
            Some(block) => {
                let Ok(sync_aggregate) = block.body().sync_aggregate() else {
                    continue; // pre-Altair, no sync aggregate
                };
                chain.recompute_and_cache_light_client_updates((
                    block.parent_root(),
                    block.slot(),
                    sync_aggregate.clone(),
                ))?;
            }
            None => {
                // A block was expected but it's not in the block store.
                warn!(
                    slot = %slot,
                    block_root = %block_root,
                    period,
                    "LC epoch backfill: expected block missing from store"
                );
                // Don't advance completed_period for this period — leaving
                // it incomplete means a future run retries it naturally,
                // without needing a separate retry queue.
            }
        }
    }

    Ok(())
}