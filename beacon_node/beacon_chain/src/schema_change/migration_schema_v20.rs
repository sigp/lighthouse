use crate::beacon_chain::{BeaconChainTypes, OP_POOL_DB_KEY};
use operation_pool::{
    PersistedOperationPool, PersistedOperationPoolV15, PersistedOperationPoolV20,
};
use slog::{debug, info, Logger};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};
use types::Attestation;

pub fn upgrade_to_v20<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!(log, "Upgrading from v19 to v20");

    // Load a V15 op pool and transform it to V20.
    let Some(PersistedOperationPoolV15::<T::EthSpec> {
        attestations_v15,
        sync_contributions,
        attester_slashings_v15,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
        capella_bls_change_broadcast_indices,
    }) = db.get_item(&OP_POOL_DB_KEY)?
    else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    let attestations = attestations_v15
        .into_iter()
        .map(|(attestation, indices)| (Attestation::Base(attestation).into(), indices))
        .collect();

    let attester_slashings = attester_slashings_v15
        .into_iter()
        .map(|slashing| slashing.into())
        .collect();

    let v20 = PersistedOperationPool::V20(PersistedOperationPoolV20 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
        capella_bls_change_broadcast_indices,
    });
    Ok(vec![v20.as_kv_store_op(OP_POOL_DB_KEY)])
}

pub fn downgrade_from_v20<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    info!(log, "Downgrading from v20 to v19");

    // Load a V20 op pool and transform it to V15.
    let Some(PersistedOperationPoolV20::<T::EthSpec> {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
        capella_bls_change_broadcast_indices,
    }) = db.get_item(&OP_POOL_DB_KEY)?
    else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    let attestations_v15 = attestations
        .into_iter()
        .filter_map(|(attestation, indices)| {
            if let Attestation::Base(attestation) = attestation.into() {
                Some((attestation, indices))
            } else {
                info!(log, "Dropping attestation during downgrade"; "reason" => "not a base attestation");
                None
            }
        })
        .collect();

    let attester_slashings_v15 = attester_slashings
        .into_iter()
        .filter_map(|slashing| match slashing.try_into() {
            Ok(slashing) => Some(slashing),
            Err(_) => {
                info!(log, "Dropping attester slashing during downgrade"; "reason" => "not a base attester slashing");
                None
            }
        })
        .collect();

    let v15 = PersistedOperationPool::V15(PersistedOperationPoolV15 {
        attestations_v15,
        sync_contributions,
        attester_slashings_v15,
        proposer_slashings,
        voluntary_exits,
        bls_to_execution_changes,
        capella_bls_change_broadcast_indices,
    });
    Ok(vec![v15.as_kv_store_op(OP_POOL_DB_KEY)])
}
