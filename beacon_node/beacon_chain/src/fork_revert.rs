use crate::{BeaconForkChoiceStore, BeaconSnapshot};
use fork_choice::ForkChoice;
use itertools::process_results;
use slog::{info, warn, Logger};
use state_processing::state_advance::complete_state_advance;
use state_processing::{per_block_processing, per_block_processing::BlockSignatureStrategy};
use std::sync::Arc;
use store::{iter::ParentRootBlockIterator, HotColdDB, ItemStore};
use types::{BeaconState, ChainSpec, EthSpec, ForkName, Hash256, SignedBeaconBlock, Slot};

const CORRUPT_DB_MESSAGE: &str = "The database could be corrupt. Check its file permissions or \
                                  consider deleting it by running with the --purge-db flag.";

/// Revert the head to the last block before the most recent hard fork.
///
/// This function is destructive and should only be used if there is no viable alternative. It will
/// cause the reverted blocks and states to be completely forgotten, lying dormant in the database
/// forever.
///
/// Return the `(head_block_root, head_block)` that should be used post-reversion.
pub fn revert_to_fork_boundary<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    current_slot: Slot,
    head_block_root: Hash256,
    store: Arc<HotColdDB<E, Hot, Cold>>,
    spec: &ChainSpec,
    log: &Logger,
) -> Result<(Hash256, SignedBeaconBlock<E>), String> {
    let current_fork = spec.fork_name_at_slot::<E>(current_slot);
    let fork_epoch = spec
        .fork_epoch(current_fork)
        .ok_or_else(|| format!("Current fork '{}' never activates", current_fork))?;

    if current_fork == ForkName::Base {
        return Err(format!(
            "Cannot revert to before phase0 hard fork. {}",
            CORRUPT_DB_MESSAGE
        ));
    }

    warn!(
        log,
        "Reverting invalid head block";
        "target_fork" => %current_fork,
        "fork_epoch" => fork_epoch,
    );
    let block_iter = ParentRootBlockIterator::fork_tolerant(&store, head_block_root);

    process_results(block_iter, |mut iter| {
        iter.find_map(|(block_root, block)| {
            if block.slot() < fork_epoch.start_slot(E::slots_per_epoch()) {
                Some((block_root, block))
            } else {
                info!(
                    log,
                    "Reverting block";
                    "block_root" => ?block_root,
                    "slot" => block.slot(),
                );
                None
            }
        })
    })
    .map_err(|e| {
        format!(
            "Error fetching blocks to revert: {:?}. {}",
            e, CORRUPT_DB_MESSAGE
        )
    })?
    .ok_or_else(|| format!("No pre-fork blocks found. {}", CORRUPT_DB_MESSAGE))
}

/// Reset fork choice to the finalized checkpoint of the supplied head state.
///
/// The supplied `head_block_root` should correspond to the most recently applied block on
/// `head_state`.
///
/// This function avoids quirks of fork choice initialization by replaying all of the blocks from
/// the checkpoint to the head.
///
/// See this issue for details: https://github.com/ethereum/consensus-specs/issues/2566
///
/// It will fail if the finalized state or any of the blocks to replay are unavailable.
///
/// WARNING: this function is destructive and causes fork choice to permanently forget all
/// chains other than the chain leading to `head_block_root`. It should only be used in extreme
/// circumstances when there is no better alternative.
pub fn reset_fork_choice_to_finalization<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    head_block_root: Hash256,
    head_state: &BeaconState<E>,
    store: Arc<HotColdDB<E, Hot, Cold>>,
    spec: &ChainSpec,
) -> Result<ForkChoice<BeaconForkChoiceStore<E, Hot, Cold>, E>, String> {
    // Fetch finalized block.
    let finalized_checkpoint = head_state.finalized_checkpoint();
    let finalized_block_root = finalized_checkpoint.root;
    let finalized_block = store
        .get_block(&finalized_block_root)
        .map_err(|e| format!("Error loading finalized block: {:?}", e))?
        .ok_or_else(|| {
            format!(
                "Finalized block missing for revert: {:?}",
                finalized_block_root
            )
        })?;

    // Advance finalized state to finalized epoch (to handle skipped slots).
    let finalized_state_root = finalized_block.state_root();
    let mut finalized_state = store
        .get_state(&finalized_state_root, Some(finalized_block.slot()))
        .map_err(|e| format!("Error loading finalized state: {:?}", e))?
        .ok_or_else(|| {
            format!(
                "Finalized block state missing from database: {:?}",
                finalized_state_root
            )
        })?;
    let finalized_slot = finalized_checkpoint.epoch.start_slot(E::slots_per_epoch());
    complete_state_advance(
        &mut finalized_state,
        Some(finalized_state_root),
        finalized_slot,
        spec,
    )
    .map_err(|e| {
        format!(
            "Error advancing finalized state to finalized epoch: {:?}",
            e
        )
    })?;
    let finalized_snapshot = BeaconSnapshot {
        beacon_block_root: finalized_block_root,
        beacon_block: finalized_block,
        beacon_state: finalized_state,
    };

    let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store.clone(), &finalized_snapshot);

    let mut fork_choice = ForkChoice::from_anchor(
        fc_store,
        finalized_block_root,
        &finalized_snapshot.beacon_block,
        &finalized_snapshot.beacon_state,
    )
    .map_err(|e| format!("Unable to reset fork choice for revert: {:?}", e))?;

    // Replay blocks from finalized checkpoint back to head.
    // We do not replay attestations presently, relying on the absence of other blocks
    // to guarantee `head_block_root` as the head.
    let blocks = store
        .load_blocks_to_replay(finalized_slot + 1, head_state.slot(), head_block_root)
        .map_err(|e| format!("Error loading blocks to replay for fork choice: {:?}", e))?;

    let mut state = finalized_snapshot.beacon_state;
    for block in blocks {
        complete_state_advance(&mut state, None, block.slot(), spec)
            .map_err(|e| format!("State advance failed: {:?}", e))?;

        per_block_processing(
            &mut state,
            &block,
            None,
            BlockSignatureStrategy::NoVerification,
            spec,
        )
        .map_err(|e| format!("Error replaying block: {:?}", e))?;

        let (block, _) = block.deconstruct();
        fork_choice
            .on_block(block.slot(), &block, block.canonical_root(), &state)
            .map_err(|e| format!("Error applying replayed block to fork choice: {:?}", e))?;
    }

    Ok(fork_choice)
}
