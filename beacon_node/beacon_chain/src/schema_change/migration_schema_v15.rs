use crate::beacon_chain::{BeaconChainTypes, OP_POOL_DB_KEY};
use operation_pool::{
    PersistedOperationPool, PersistedOperationPoolV14, PersistedOperationPoolV15,
};
use slog::{debug, info, Logger};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

pub fn upgrade_to_v15<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V14 op pool and transform it to V15.
    let PersistedOperationPoolV14::<T::EthSpec> {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
    } = if let Some(op_pool_v14) = db.get_item(&OP_POOL_DB_KEY)? {
        op_pool_v14
    } else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    let v15 = PersistedOperationPool::V15(PersistedOperationPoolV15 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
        // Initialize with empty set
        capella_bls_change_broadcast_indices: <_>::default(),
    });
    Ok(vec![v15.as_kv_store_op(OP_POOL_DB_KEY)])
}

pub fn downgrade_from_v15<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V15 op pool and transform it to V14.
    let PersistedOperationPoolV15::<T::EthSpec> {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
        capella_bls_change_broadcast_indices,
    } = if let Some(op_pool) = db.get_item(&OP_POOL_DB_KEY)? {
        op_pool
    } else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    info!(
        log,
        "Forgetting address changes for Capella broadcast";
        "count" => capella_bls_change_broadcast_indices.len(),
    );

    let v14 = PersistedOperationPoolV14 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
    };
    Ok(vec![v14.as_kv_store_op(OP_POOL_DB_KEY)])
}
