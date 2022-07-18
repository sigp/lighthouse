use crate::beacon_chain::{BeaconChainTypes, OP_POOL_DB_KEY};
use operation_pool::{PersistedOperationPool, PersistedOperationPoolV11, PersistedOperationPoolV5};
use slog::{debug, Logger};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

pub fn upgrade_to_v11<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V5 op pool and transform it to V11.
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
    let v11 = PersistedOperationPool::V11(PersistedOperationPoolV11 {
        attestations: vec![],
        sync_contributions: v5.sync_contributions,
        attester_slashings: v5.attester_slashings,
        proposer_slashings: v5.proposer_slashings,
        voluntary_exits: v5.voluntary_exits,
    });
    Ok(vec![v11.as_kv_store_op(OP_POOL_DB_KEY)])
}

pub fn downgrade_from_v11<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V11 op pool and transform it to V5.
    let v11 = if let Some(PersistedOperationPool::V11(op_pool)) =
        db.get_item::<PersistedOperationPool<T::EthSpec>>(&OP_POOL_DB_KEY)?
    {
        op_pool
    } else {
        return Ok(vec![]);
    };

    debug!(
        log,
        "Dropping attestations from pool";
        "count" => v11.attestations.len(),
    );

    let v5 = PersistedOperationPoolV5 {
        attestations_v5: vec![],
        sync_contributions: v11.sync_contributions,
        attester_slashings: v11.attester_slashings,
        proposer_slashings: v11.proposer_slashings,
        voluntary_exits: v11.voluntary_exits,
    };
    Ok(vec![v5.as_kv_store_op(OP_POOL_DB_KEY)])
}
