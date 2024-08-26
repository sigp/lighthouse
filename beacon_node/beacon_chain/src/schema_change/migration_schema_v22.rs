use crate::beacon_chain::BeaconChainTypes;
use slog::error;
use slog::{info, Logger};
use std::sync::Arc;
use store::chunked_iter::ChunkedVectorIter;
use store::{
    chunked_vector::BlockRoots, get_key_for_col, partial_beacon_state::PartialBeaconState,
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
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!(log, "Upgrading from v21 to v22");

    let anchor = db.get_anchor_info();
    let split_slot = db.get_split_slot();
    let genesis_state_root = genesis_state_root.ok_or(Error::GenesisStateUnknown)?;

    if !db.get_config().allow_tree_states_migration
        && anchor
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

    let mut ops = vec![];

    let oldest_block_slot = anchor.map_or(Slot::new(0), |a| a.oldest_block_slot);
    rewrite_block_roots::<T>(&db, oldest_block_slot, split_slot, &mut ops, &log)?;

    let mut genesis_state = load_old_schema_frozen_state::<T>(&db, genesis_state_root)?
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
