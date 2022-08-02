use crate::beacon_chain::{BeaconChainTypes, OP_POOL_DB_KEY};
use operation_pool::{PersistedOperationPool, PersistedOperationPoolV12, PersistedOperationPoolV5};
use slog::{debug, info, Logger};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

pub fn upgrade_to_v12<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V5 op pool and transform it to V12.
    let v5 = if let Some(op_pool) =
        db.get_item::<PersistedOperationPoolV5<T::EthSpec>>(&OP_POOL_DB_KEY)?
    {
        op_pool
    } else {
        return Ok(vec![]);
    };

    debug!(
        log,
        "Dropping attestations from pool";
        "count" => v5.attestations_v5.len(),
    );

    // FIXME(sproul): work out whether it's worth trying to carry across the attestations
    let v12 = PersistedOperationPool::V12(PersistedOperationPoolV12 {
        attestations: vec![],
        sync_contributions: v5.sync_contributions,
        attester_slashings: v5.attester_slashings,
        proposer_slashings: v5.proposer_slashings,
        voluntary_exits: v5.voluntary_exits,
    });
    Ok(vec![v12.as_kv_store_op(OP_POOL_DB_KEY)])
}

pub fn downgrade_from_v12<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V12 op pool and transform it to V5.
    let v12 = if let Some(PersistedOperationPool::V12(op_pool)) =
        db.get_item::<PersistedOperationPool<T::EthSpec>>(&OP_POOL_DB_KEY)?
    {
        op_pool
    } else {
        return Ok(vec![]);
    };

    info!(
        log,
        "Dropping attestations from pool";
        "count" => v12.attestations.len(),
    );

    let v5 = PersistedOperationPoolV5 {
        attestations_v5: vec![],
        sync_contributions: v12.sync_contributions,
        attester_slashings: v12.attester_slashings,
        proposer_slashings: v12.proposer_slashings,
        voluntary_exits: v12.voluntary_exits,
    };
    Ok(vec![v5.as_kv_store_op(OP_POOL_DB_KEY)])
}
