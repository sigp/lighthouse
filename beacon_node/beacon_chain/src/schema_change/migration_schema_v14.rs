use crate::beacon_chain::{BeaconChainTypes, OP_POOL_DB_KEY};
use operation_pool::{
    PersistedOperationPool, PersistedOperationPoolV12, PersistedOperationPoolV14,
};
use slog::{debug, error, info, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};
use types::{EthSpec, Hash256, Slot};

/// The slot clock isn't usually available before the database is initialized, so we construct a
/// temporary slot clock by reading the genesis state. It should always exist if the database is
/// initialized at a prior schema version, however we still handle the lack of genesis state
/// gracefully.
fn get_slot_clock<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    log: &Logger,
) -> Result<Option<T::SlotClock>, Error> {
    let spec = db.get_chain_spec();
    let genesis_block = if let Some(block) = db.get_blinded_block(&Hash256::zero())? {
        block
    } else {
        error!(log, "Missing genesis block");
        return Ok(None);
    };
    let genesis_state =
        if let Some(state) = db.get_state(&genesis_block.state_root(), Some(Slot::new(0)))? {
            state
        } else {
            error!(log, "Missing genesis state"; "state_root" => ?genesis_block.state_root());
            return Ok(None);
        };
    Ok(Some(T::SlotClock::new(
        spec.genesis_slot,
        Duration::from_secs(genesis_state.genesis_time()),
        Duration::from_secs(spec.seconds_per_slot),
    )))
}

pub fn upgrade_to_v14<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V12 op pool and transform it to V14.
    let PersistedOperationPoolV12::<T::EthSpec> {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
    } = if let Some(op_pool_v12) = db.get_item(&OP_POOL_DB_KEY)? {
        op_pool_v12
    } else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    // initialize with empty vector
    let bls_to_execution_changes = vec![];
    let v14 = PersistedOperationPool::V14(PersistedOperationPoolV14 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
    });
    Ok(vec![v14.as_kv_store_op(OP_POOL_DB_KEY)])
}

pub fn downgrade_from_v14<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // We cannot downgrade from V14 once the Capella fork has been reached because there will
    // be HistoricalSummaries stored in the database instead of HistoricalRoots and prior versions
    // of Lighthouse can't handle that.
    if let Some(capella_fork_epoch) = db.get_chain_spec().capella_fork_epoch {
        let current_epoch = get_slot_clock::<T>(&db, &log)?
            .and_then(|clock| clock.now())
            .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
            .ok_or(Error::SlotClockUnavailableForMigration)?;

        if current_epoch >= capella_fork_epoch {
            error!(
                log,
                "Capella already active: v14+ is mandatory";
                "current_epoch" => current_epoch,
                "capella_fork_epoch" => capella_fork_epoch,
            );
            return Err(Error::UnableToDowngrade);
        }
    }

    // Load a V14 op pool and transform it to V12.
    let PersistedOperationPoolV14::<T::EthSpec> {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
    } = if let Some(op_pool) = db.get_item(&OP_POOL_DB_KEY)? {
        op_pool
    } else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    info!(
        log,
        "Dropping bls_to_execution_changes from pool";
        "count" => bls_to_execution_changes.len(),
    );

    let v12 = PersistedOperationPoolV12 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
    };
    Ok(vec![v12.as_kv_store_op(OP_POOL_DB_KEY)])
}
