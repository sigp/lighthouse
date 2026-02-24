use crate::BeaconForkChoiceStore;
use fork_choice::ForkChoice;
use itertools::process_results;
use std::sync::Arc;
use store::{HotColdDB, ItemStore, iter::ParentRootBlockIterator};
use tracing::{info, warn};
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
        target_fork = %current_fork,
        %fork_epoch,
        "Reverting invalid head block"
    );
    let block_iter = ParentRootBlockIterator::fork_tolerant(&store, head_block_root);

    let (block_root, blinded_block) = process_results(block_iter, |mut iter| {
        iter.find_map(|(block_root, block)| {
            if block.slot() < fork_epoch.start_slot(E::slots_per_epoch()) {
                Some((block_root, block))
            } else {
                info!(
                    ?block_root,
                    slot = %block.slot(),
                    "Reverting block"
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
    .ok_or_else(|| format!("No pre-fork blocks found. {}", CORRUPT_DB_MESSAGE))?;

    let block = store
        .make_full_block(&block_root, blinded_block)
        .map_err(|e| format!("Unable to add payload to new head block: {:?}", e))?;

    Ok((block_root, block))
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
    _head_block_root: Hash256,
    _head_state: &BeaconState<E>,
    _store: Arc<HotColdDB<E, Hot, Cold>>,
    _current_slot: Option<Slot>,
    _spec: &ChainSpec,
) -> Result<ForkChoice<BeaconForkChoiceStore<E, Hot, Cold>, E>, String> {
    Err("broken".into())
}
