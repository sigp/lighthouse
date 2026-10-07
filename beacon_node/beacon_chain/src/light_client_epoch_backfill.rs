use crate::{BeaconChain, BeaconChainError as Error, BeaconChainTypes, WhenSlotSkipped};
use ssz_types::{FixedVector, VariableList};
use store::metadata::{LC_EPOCH_BACKFILL_PROGRESS_KEY, LightClientEpochBackfillProgress};
use tracing::warn;
use types::{
    ChainSpec, Checkpoint, Epoch, EthSpec, ExecPayload, Hash256, LightClientBlockData,
    LightClientBootstrapData, LightClientEpochData,
};

/// Walks finalized sync committee periods forward from the node's
/// earliest available state up to the most recently finalized period 
/// computing and persisting `LightClientEpochData` for each one.
/// This function assumes it's already been decided that backfill should run.
/// Hence, gating (opt-in flag, etc) is the caller's job
///
/// Returns `Ok(true)` when it has caught up to `newest_epoch` cleanly, `Ok(false)` when it
/// stopped early due to a missing block (caller should back off and retry later).
pub fn backfill_light_client_epoch_data<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<bool, Error> {
    let spec = &chain.spec;
    let slots_per_epoch = T::EthSpec::slots_per_epoch();

    // `LightClientEpochData` for an epoch is only immutable once that epoch is finalized
    // (a later fork could otherwise change which blocks ended up in it), so the newest
    // epoch we can safely compute is the one just before the current finalized epoch.
    let finalized_epoch = chain
        .canonical_head
        .fork_choice_read_lock()
        .finalized_checkpoint()
        .epoch;
    let newest_epoch = finalized_epoch.saturating_sub(1u64);

    let (_state_lower_limit, state_upper_limit) = chain.store.get_historic_state_limits();
    let oldest_epoch = state_upper_limit.epoch(slots_per_epoch);

    let start_epoch = chain
        .store
        .get_item::<LightClientEpochBackfillProgress>(&LC_EPOCH_BACKFILL_PROGRESS_KEY)?
        .map(|progress| progress.0.saturating_add(1))
        .unwrap_or_else(|| oldest_epoch.as_u64());

    for epoch_u64 in start_epoch..=newest_epoch.as_u64() {
        let epoch = Epoch::new(epoch_u64);
        let clean = backfill_epoch(chain, epoch, spec, slots_per_epoch)?;
        if !clean {
            return Ok(false);
        }
        chain.store.put_item(
            &LC_EPOCH_BACKFILL_PROGRESS_KEY,
            &LightClientEpochBackfillProgress(epoch_u64),
        )?;
    }
    Ok(true)
}

fn backfill_epoch<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    epoch: Epoch,
    spec: &ChainSpec,
    slots_per_epoch: u64,
) -> Result<bool, Error> {
    let fork_name = spec.fork_name_at_epoch(epoch);

    let prev_epoch_start_slot = epoch.saturating_sub(1u64).start_slot(slots_per_epoch);
    let Some(parent_block_root) =
        chain.block_root_at_slot(prev_epoch_start_slot, WhenSlotSkipped::Prev)?
    else {
        warn!(%epoch, "LC epoch backfill: no parent block found before epoch start");
        return Ok(false);
    };
    let Some(parent_block) = chain.store.get_blinded_block(&parent_block_root)? else {
        warn!(%epoch, %parent_block_root, "LC epoch backfill: parent block root not in store");
        return Ok(false);
    };
    let parent_block_header = parent_block.message().block_header();

    // Per-slot `LightClientBlockData` for every slot in the epoch; skipped slots get the
    // `Default` value, matching the spec's "empty slots are default-initialized" rule.
    let start_slot = epoch.start_slot(slots_per_epoch);
    let end_slot = start_slot + slots_per_epoch - 1;
    let mut block_data = vec![LightClientBlockData::default(); slots_per_epoch as usize];
    let mut last_block_in_epoch = None;

    let mut last_root: Option<Hash256> = None;
    for result in chain.forwards_iter_block_roots_until(start_slot, end_slot)? {
        let (block_root, slot) = result?;
        if last_root == Some(block_root) {
            continue;
        }
        last_root = Some(block_root);

        let offset = (slot - start_slot).as_usize();
        let Some(block) = chain.store.get_blinded_block(&block_root)? else {
            warn!(%slot, %block_root, %epoch, "LC epoch backfill: expected block missing from store");
            return Ok(false);
        };
        block_data[offset] = LightClientBlockData::from_block(&block)?;
        last_block_in_epoch = Some(block);
    }

    // `bootstrap_data`'s `current_sync_committee_branch`/`execution_branch` are proofs
    // against this epoch's last available block/state, computed unconditionally; only
    // the `current_sync_committee` *value* is non-empty when this epoch is the last of a
    // fully-finalized sync committee period (per the struct's own doc comment).
    let anchor_block = last_block_in_epoch.as_ref().unwrap_or(&parent_block);
    let anchor_state_root = anchor_block.state_root();
    let Some(mut anchor_state) = chain.get_state(&anchor_state_root, Some(anchor_block.slot()), false)?
    else {
        warn!(%epoch, state_root = %anchor_state_root, "LC epoch backfill: anchor state missing from store");
        return Ok(false);
    };
    // A freshly loaded state can have pending milhouse updates 
    // that must be applied before hashing.
    anchor_state.apply_pending_mutations()?;

    let current_sync_committee_branch = anchor_state.compute_current_sync_committee_proof()?;
    let is_period_checkpoint = {
        let period = epoch.sync_committee_period(spec)?;
        let next_period = (epoch + 1u64).sync_committee_period(spec)?;
        let finalized_period = chain
            .canonical_head
            .fork_choice_read_lock()
            .finalized_checkpoint()
            .epoch
            .sync_committee_period(spec)?;
        period != next_period && period <= finalized_period
    };
    let current_sync_committee = if is_period_checkpoint {
        VariableList::new(vec![anchor_state.current_sync_committee()?.clone()])
            .map_err(|e| Error::LightClientError(e.into()))?
    } else {
        VariableList::empty()
    };

    // Altair/Bellatrix use the Altair-era light client header, which has no execution
    // fields at all — so only compute these from Capella onward.
    let execution = if fork_name.capella_enabled() {
        let execution_branch = anchor_block
            .message()
            .body()
            .block_body_merkle_proof(types::light_client::consts::EXECUTION_PAYLOAD_INDEX)
            .map_err(Error::BeaconStateError)?;
        let execution_block_hash = anchor_block
            .message()
            .body()
            .execution_payload()
            .map_err(Error::BeaconStateError)?
            .block_hash()
            .0;
        Some((execution_block_hash, execution_branch))
    } else {
        None
    };

    let bootstrap_data = LightClientBootstrapData::new(
        current_sync_committee,
        current_sync_committee_branch,
        execution,
        fork_name,
    )
    .map_err(Error::LightClientError)?;

    let finalized_checkpoint: Checkpoint = anchor_state.finalized_checkpoint();
    let finalized_checkpoint_branch = anchor_state.compute_finalized_root_proof()?;

    let epoch_data = LightClientEpochData::new(
        epoch,
        parent_block_header,
        FixedVector::new(block_data).map_err(|e| Error::LightClientError(e.into()))?,
        bootstrap_data,
        finalized_checkpoint,
        finalized_checkpoint_branch,
        fork_name,
    )
    .map_err(Error::LightClientError)?;

    chain.store.store_light_client_epoch_data(epoch, &epoch_data)?;

    Ok(true)
}