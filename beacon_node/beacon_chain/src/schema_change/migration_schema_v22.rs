use crate::beacon_chain::BeaconChainTypes;
use slog::{info, Logger};
use std::sync::Arc;
use store::chunked_iter::ChunkedVectorIter;
use store::{
    chunked_vector::BlockRootsChunked,
    get_key_for_col,
    metadata::{
        SchemaVersion, ANCHOR_FOR_ARCHIVE_NODE, ANCHOR_UNINITIALIZED, STATE_UPPER_LIMIT_NO_RETAIN,
    },
    partial_beacon_state::PartialBeaconState,
    AnchorInfo, DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp,
};
use types::{BeaconState, Hash256, Slot};

const LOG_EVERY: usize = 200_000;

fn load_old_schema_frozen_state<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    state_root: Hash256,
) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
    let Some(partial_state_bytes) = db
        .cold_db
        .get_bytes(DBColumn::BeaconState.into(), state_root.as_slice())?
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

    // If the anchor was uninitialized in the old schema (`None`), this represents a full archive
    // node.
    let effective_anchor = if old_anchor == ANCHOR_UNINITIALIZED {
        ANCHOR_FOR_ARCHIVE_NODE
    } else {
        old_anchor.clone()
    };

    let split_slot = db.get_split_slot();
    let genesis_state_root = genesis_state_root.ok_or(Error::GenesisStateUnknown)?;

    let mut cold_ops = vec![];

    // Load the genesis state in the previous chunked format, BEFORE we go deleting or rewriting
    // anything.
    let mut genesis_state = load_old_schema_frozen_state::<T>(&db, genesis_state_root)?
        .ok_or(Error::MissingGenesisState)?;
    let genesis_state_root = genesis_state.update_tree_hash_cache()?;
    let genesis_block_root = genesis_state.get_latest_block_root(genesis_state_root);

    // Store the genesis state in the new format, prior to updating the schema version on disk.
    // In case of a crash no data is lost because we will re-load it in the old format and re-do
    // this write.
    if split_slot > 0 {
        info!(
            log,
            "Re-storing genesis state";
            "state_root" => ?genesis_state_root,
        );
        db.store_cold_state(&genesis_state_root, &genesis_state, &mut cold_ops)?;
    }

    // Write the block roots in the new format in a new column. Similar to above, we do this
    // separately from deleting the old format block roots so that this is crash safe.
    let oldest_block_slot = effective_anchor.oldest_block_slot;
    write_new_schema_block_roots::<T>(
        &db,
        genesis_block_root,
        oldest_block_slot,
        split_slot,
        &mut cold_ops,
        &log,
    )?;

    // Commit this first batch of non-destructive cold database ops.
    db.cold_db.do_atomically(cold_ops)?;

    // Now we update the anchor and the schema version atomically in the hot database.
    //
    // If we crash after commiting this change, then there will be some leftover cruft left in the
    // freezer database, but no corruption because all the new-format data has already been written
    // above.
    let new_anchor = AnchorInfo {
        state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
        state_lower_limit: Slot::new(0),
        ..effective_anchor.clone()
    };
    let hot_ops = vec![db.compare_and_set_anchor_info(old_anchor, new_anchor)?];
    db.store_schema_version_atomically(SchemaVersion(22), hot_ops)?;

    // Finally, clean up the old-format data from the freezer database.
    delete_old_schema_freezer_data::<T>(&db, &log)?;

    Ok(())
}

pub fn delete_old_schema_freezer_data<T: BeaconChainTypes>(
    db: &Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: &Logger,
) -> Result<(), Error> {
    let mut cold_ops = vec![];

    let columns = [
        DBColumn::BeaconState,
        // Cold state summaries indexed by state root were stored in this column.
        DBColumn::BeaconStateSummary,
        // Mapping from restore point number to state root was stored in this column.
        DBColumn::BeaconRestorePoint,
        // Chunked vector values were stored in these columns.
        DBColumn::BeaconHistoricalRoots,
        DBColumn::BeaconRandaoMixes,
        DBColumn::BeaconHistoricalSummaries,
        DBColumn::BeaconBlockRootsChunked,
        DBColumn::BeaconStateRootsChunked,
    ];

    for column in columns {
        for res in db.cold_db.iter_column_keys::<Vec<u8>>(column) {
            let key = res?;
            cold_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
                column.as_str(),
                &key,
            )));
        }
    }
    let delete_ops = cold_ops.len();

    info!(
        log,
        "Deleting historic states";
        "delete_ops" => delete_ops,
    );
    db.cold_db.do_atomically(cold_ops)?;

    // In order to reclaim space, we need to compact the freezer DB as well.
    db.compact_freezer()?;

    Ok(())
}

pub fn write_new_schema_block_roots<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    genesis_block_root: Hash256,
    oldest_block_slot: Slot,
    split_slot: Slot,
    cold_ops: &mut Vec<KeyValueStoreOp>,
    log: &Logger,
) -> Result<(), Error> {
    info!(
        log,
        "Starting beacon block root migration";
        "oldest_block_slot" => oldest_block_slot,
        "genesis_block_root" => ?genesis_block_root,
    );

    // Store the genesis block root if it would otherwise not be stored.
    if oldest_block_slot != 0 {
        cold_ops.push(KeyValueStoreOp::PutKeyValue(
            get_key_for_col(DBColumn::BeaconBlockRoots.into(), &0u64.to_be_bytes()),
            genesis_block_root.as_slice().to_vec(),
        ));
    }

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
        cold_ops.push(KeyValueStoreOp::PutKeyValue(
            get_key_for_col(
                DBColumn::BeaconBlockRoots.into(),
                &(slot as u64).to_be_bytes(),
            ),
            block_root.as_slice().to_vec(),
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
