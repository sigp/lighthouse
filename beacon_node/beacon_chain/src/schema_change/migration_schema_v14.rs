use crate::beacon_chain::{BeaconChainTypes, OP_POOL_DB_KEY};
use operation_pool::{
    PersistedOperationPool, PersistedOperationPoolV12, PersistedOperationPoolV14,
};
use slog::{debug, info, Logger};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

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
    // Load a V14 op pool and transform it to V12.
    let PersistedOperationPoolV14 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
    } = if let Some(PersistedOperationPool::<T::EthSpec>::V14(op_pool)) =
        db.get_item(&OP_POOL_DB_KEY)?
    {
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
