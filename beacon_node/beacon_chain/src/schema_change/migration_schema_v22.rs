use crate::beacon_chain::BeaconChainTypes;
use slog::error;
use slog::{info, Logger};
use std::sync::Arc;
use store::chunked_iter::ChunkedVectorIter;
use store::{
    chunked_vector::BlockRootsChunked, get_key_for_col, partial_beacon_state::PartialBeaconState,
    DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp,
};
use types::{BeaconState, Hash256, Slot};

const LOG_EVERY: usize = 200_000;

fn load_old_schema_frozen_state<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    state_root: Hash256,
) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
    let Some(partial_state_bytes) = db
        .cold_db
        .get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())?
    else {
        return Ok(None);
    };
    let mut partial_state: PartialBeaconState<T::EthSpec> =
        PartialBeaconState::from_ssz_bytes(&partial_state_bytes, db.get_chain_spec())?;

    // Fill in the fields of the partial state.
    partial_state.load_block_roots(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_state_roots(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_historical_roots(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_randao_mixes(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_historical_summaries(&db.cold_db, db.get_chain_spec())?;

    partial_state.try_into().map(Some)
}

pub fn upgrade_to_v22<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    genesis_state_root: Option<Hash256>,
    log: Logger,
) -> Result<(), Error> {
    info!(log, "Upgrading from v21 to v22");

    let old_anchor = db.get_anchor_info();
    let split_slot = db.get_split_slot();
    let genesis_state_root = genesis_state_root.ok_or(Error::GenesisStateUnknown)?;

    if !db.get_config().allow_tree_states_migration
        && old_anchor
            .as_ref()
            .map_or(true, |anchor| !anchor.no_historic_states_stored(split_slot))
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

    let mut cold_ops = vec![];

    // Load the genesis state in the previous chunked format, BEFORE we go deleting or rewriting
    // anything.
    let mut genesis_state = load_old_schema_frozen_state::<T>(&db, genesis_state_root)?
        .ok_or(Error::MissingGenesisState)?;
    let genesis_state_root = genesis_state.update_tree_hash_cache()?;

    // Store the genesis state in the new format, prior to updating the schema version on disk.
    // In case of a crash no data is lost because we will re-load it in the old format and re-do
    // this write.
    if split_slot > 0 {
        info!(
            self.log,
            "Re-storing genesis state";
            "state_root" => ?genesis_state_root,
        );
        self.store_cold_state(&genesis_state_root, genesis_state, &mut cold_ops)?;
    }

    // Write the block roots in the new format. Similar to above, we do this separately from
    // deleting the old format block roots so that this is crash safe.
    let oldest_block_slot = old_anchor.map_or(Slot::new(0), |a| a.oldest_block_slot);
    rewrite_block_roots::<T>(&db, oldest_block_slot, split_slot, &mut cold_ops, &log)?;

    // Commit this first batch of non-destructive cold database ops.
    db.cold_db.do_atomically(cold_ops)?;

    // Now we update the anchor and the schema version atomically in the hot database.
    //
    // If we crash after commiting this change, then there will be some leftover cruft left in the
    // freezer database, but no corruption because all the new-format data has already been written
    // above.
    let new_anchor = if let Some(old_anchor) = &old_anchor {
        AnchorInfo {
            state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
            state_lower_limit: Slot::new(0),
            ..old_anchor.clone()
        }
    } else {
        AnchorInfo {
            anchor_slot: Slot::new(0),
            oldest_block_slot: Slot::new(0),
            oldest_block_parent: Hash256::zero(),
            state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
            state_lower_limit: Slot::new(0),
        }
    };
    let hot_ops = vec![db.compare_and_set_anchor_info(anchor, Some(new_anchor))?];
    db.store_schema_version_atomically(SchemaVersion(22), hot_ops)?;

    // Finally, clean up the old-format data from the freezer database.
    db.prune_historic_states(genesis_state_root, &genesis_state)?;

    Ok(ops)
}

pub fn delete_old_schema_freezer_data<T: BeaconChainTypes>() -> Result<(), Error> {
    let mut cold_ops = vec![];

    let columns = [
        DBColumn::BeaconState,
        DBColumn::BeaconStateSummary, // FIXME: ?
        DBColumn::BeaconRestorePoint,
        DBColumn::BeaconHistoricalRoots,
        DBColumn::BeaconRandaoMixes,
        DBColumn::BeaconHistoricalSummaries,
        DBColumn::BeaconBlockRootsChunked,
        DBColumn::BeaconStateRoots, // FIXME: ?
    ];

    for column in columns {
        for res in self.cold_db.iter_column_keys::<Vec<u8>>(column) {
            let key = res?;
            cold_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
                column.as_str(),
                &key,
            )));
        }
    }
    let delete_ops = cold_ops.len();

    info!(
        self.log,
        "Deleting historic states";
        "delete_ops" => delete_ops,
    );
    self.cold_db.do_atomically(cold_ops)?;

    // In order to reclaim space, we need to compact the freezer DB as well.
    self.cold_db.compact()?;

    Ok(())
}

pub fn rewrite_block_roots<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    oldest_block_slot: Slot,
    split_slot: Slot,
    cold_ops: &mut Vec<KeyValueStoreOp>,
    log: &Logger,
) -> Result<(), Error> {
    // FIXME(sproul): think about the genesis block root (should store slot 0 ->
    // genesis_block_root)?
    // INVARIANT: TODO
    info!(
        log,
        "Starting beacon block root migration";
        "oldest_block_slot" => oldest_block_slot,
    );

    // Block roots are available from the `oldest_block_slot` to the `split_slot`.
    let start_vindex = oldest_block_slot.as_usize();
    let block_root_iter = ChunkedVectorIter::<BlockRootsChunked, _, _, _>::new(
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
