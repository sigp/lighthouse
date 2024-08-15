use crate::beacon_chain::BeaconChainTypes;
use slog::error;
use slog::{info, Logger};
use std::sync::Arc;
use store::chunked_iter::ChunkedVectorIter;
use store::{
    chunked_vector::BlockRoots, get_key_for_col, DBColumn, Error, HotColdDB, KeyValueStoreOp,
};
use types::Slot;

const LOG_EVERY: usize = 200_000;

pub fn upgrade_to_v22<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!(log, "Upgrading from v21 to v22");

    let anchor = db.get_anchor_info().ok_or(Error::NoAnchorInfo)?;
    let split_slot = db.get_split_slot();

    if !db.get_config().allow_tree_states_migration && !anchor.no_historic_states_stored(split_slot)
    {
        error!(
            log,
            "You are attempting to migrate to tree-states but this is a destructive operation. \
             Upgrading will require FIXME(sproul) minutes of downtime before Lighthouse starts again. \
             All current historic states will be deleted. Reconstructing the states in the new \
             schema will take up to 2 weeks. \
             \
             To proceed add the flag --allow-tree-states-migration OR run lighthouse db prune-states"
        );
        return Err(Error::DestructiveFreezerUpgrade);
    }

    let mut ops = vec![];

    rewrite_block_roots::<T>(&db, anchor.oldest_block_slot, split_slot, &mut ops, &log)?;

    let mut genesis_state = db
        .load_cold_state_by_slot(Slot::new(0))?
        .ok_or(Error::MissingGenesisState)?;
    let genesis_state_root = genesis_state.update_tree_hash_cache()?;

    db.prune_historic_states(genesis_state_root, &genesis_state)?;

    Ok(ops)
}

pub fn rewrite_block_roots<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    oldest_block_slot: Slot,
    split_slot: Slot,
    ops: &mut Vec<KeyValueStoreOp>,
    log: &Logger,
) -> Result<(), Error> {
    // Block roots are available from the `oldest_block_slot` to the `split_slot`.
    let start_vindex = oldest_block_slot.as_usize();
    let block_root_iter = ChunkedVectorIter::<BlockRoots, _, _, _>::new(
        db,
        start_vindex,
        split_slot,
        db.get_chain_spec(),
    );

    // OK to hold these in memory (10M slots * 43 bytes per KV ~= 430 MB).
    for (i, (slot, block_root)) in block_root_iter.enumerate() {
        ops.push(KeyValueStoreOp::PutKeyValue(
            get_key_for_col(
                DBColumn::BeaconBlockRoots.into(),
                &(slot as u64).to_be_bytes(),
            ),
            block_root.as_bytes().to_vec(),
        ));

        if i > 0 && i % LOG_EVERY == 0 {
            info!(
                log,
                "Beacon block root migration in progress";
                "roots_migrated" => i
            );
        }
    }

    Ok(())
}
