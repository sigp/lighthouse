use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY, OP_POOL_DB_KEY};
use crate::persisted_fork_choice::PersistedForkChoiceV11;
use operation_pool::{PersistedOperationPool, PersistedOperationPoolV12, PersistedOperationPoolV5};
use slog::{debug, info, Logger};
use state_processing::{
    common::get_indexed_attestation, per_block_processing::is_valid_indexed_attestation,
    VerifyOperation, VerifySignatures,
};
use std::sync::Arc;
use store::{Error, HotColdDB, KeyValueStoreOp, StoreItem};

pub fn upgrade_to_v12<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let spec = db.get_chain_spec();

    // Load a V5 op pool and transform it to V12.
    let PersistedOperationPoolV5 {
        attestations_v5,
        sync_contributions,
        attester_slashings_v5,
        proposer_slashings_v5,
        voluntary_exits_v5,
    } = if let Some(op_pool) = db.get_item(&OP_POOL_DB_KEY)? {
        op_pool
    } else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    // Load the persisted fork choice so we can grab the state of the justified block and use
    // it to verify the stored attestations, slashings and exits.
    let fork_choice = db
        .get_item::<PersistedForkChoiceV11>(&FORK_CHOICE_DB_KEY)?
        .ok_or_else(|| Error::SchemaMigrationError("fork choice missing from database".into()))?;
    let justified_block_root = fork_choice
        .fork_choice_store
        .unrealized_justified_checkpoint
        .root;
    let justified_block = db
        .get_blinded_block(&justified_block_root)?
        .ok_or_else(|| {
            Error::SchemaMigrationError(format!(
                "unrealized justified block missing for migration: {justified_block_root:?}",
            ))
        })?;
    let justified_state_root = justified_block.state_root();
    let mut state = db
        .get_state(&justified_state_root, Some(justified_block.slot()))?
        .ok_or_else(|| {
            Error::SchemaMigrationError(format!(
                "justified state missing for migration: {justified_state_root:?}"
            ))
        })?;
    state.build_all_committee_caches(spec).map_err(|e| {
        Error::SchemaMigrationError(format!("unable to build committee caches: {e:?}"))
    })?;

    // Re-verify attestations while adding attesting indices.
    let attestations = attestations_v5
        .into_iter()
        .flat_map(|(_, attestations)| attestations)
        .filter_map(|attestation| {
            let res = state
                .get_beacon_committee(attestation.data.slot, attestation.data.index)
                .map_err(Into::into)
                .and_then(|committee| get_indexed_attestation(committee.committee, &attestation))
                .and_then(|indexed_attestation| {
                    is_valid_indexed_attestation(
                        &state,
                        &indexed_attestation,
                        VerifySignatures::True,
                        spec,
                    )?;
                    Ok(indexed_attestation)
                });

            match res {
                Ok(indexed) => Some((attestation, indexed.attesting_indices.into())),
                Err(e) => {
                    debug!(
                        log,
                        "Dropping attestation on migration";
                        "err" => ?e,
                        "head_block" => ?attestation.data.beacon_block_root,
                    );
                    None
                }
            }
        })
        .collect::<Vec<_>>();

    let attester_slashings = attester_slashings_v5
        .iter()
        .filter_map(|(slashing, _)| {
            slashing
                .clone()
                .validate(&state, spec)
                .map_err(|e| {
                    debug!(
                        log,
                        "Dropping attester slashing on migration";
                        "err" => ?e,
                        "slashing" => ?slashing,
                    );
                })
                .ok()
        })
        .collect::<Vec<_>>();

    let proposer_slashings = proposer_slashings_v5
        .iter()
        .filter_map(|slashing| {
            slashing
                .clone()
                .validate(&state, spec)
                .map_err(|e| {
                    debug!(
                        log,
                        "Dropping proposer slashing on migration";
                        "err" => ?e,
                        "slashing" => ?slashing,
                    );
                })
                .ok()
        })
        .collect::<Vec<_>>();

    let voluntary_exits = voluntary_exits_v5
        .iter()
        .filter_map(|exit| {
            exit.clone()
                .validate(&state, spec)
                .map_err(|e| {
                    debug!(
                        log,
                        "Dropping voluntary exit on migration";
                        "err" => ?e,
                        "exit" => ?exit,
                    );
                })
                .ok()
        })
        .collect::<Vec<_>>();

    debug!(
        log,
        "Migrated op pool";
        "attestations" => attestations.len(),
        "attester_slashings" => attester_slashings.len(),
        "proposer_slashings" => proposer_slashings.len(),
        "voluntary_exits" => voluntary_exits.len()
    );

    let v12 = PersistedOperationPool::V12(PersistedOperationPoolV12 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
    });
    Ok(vec![v12.as_kv_store_op(OP_POOL_DB_KEY)])
}

pub fn downgrade_from_v12<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // Load a V12 op pool and transform it to V5.
    let PersistedOperationPoolV12 {
        attestations,
        sync_contributions,
        attester_slashings,
        proposer_slashings,
        voluntary_exits,
    } = if let Some(PersistedOperationPool::<T::EthSpec>::V12(op_pool)) =
        db.get_item(&OP_POOL_DB_KEY)?
    {
        op_pool
    } else {
        debug!(log, "Nothing to do, no operation pool stored");
        return Ok(vec![]);
    };

    info!(
        log,
        "Dropping attestations from pool";
        "count" => attestations.len(),
    );

    let attester_slashings_v5 = attester_slashings
        .into_iter()
        .filter_map(|slashing| {
            let fork_version = slashing.first_fork_verified_against()?;
            Some((slashing.into_inner(), fork_version))
        })
        .collect::<Vec<_>>();

    let proposer_slashings_v5 = proposer_slashings
        .into_iter()
        .map(|slashing| slashing.into_inner())
        .collect::<Vec<_>>();

    let voluntary_exits_v5 = voluntary_exits
        .into_iter()
        .map(|exit| exit.into_inner())
        .collect::<Vec<_>>();

    info!(
        log,
        "Migrated slashings and exits";
        "attester_slashings" => attester_slashings_v5.len(),
        "proposer_slashings" => proposer_slashings_v5.len(),
        "voluntary_exits" => voluntary_exits_v5.len(),
    );

    let v5 = PersistedOperationPoolV5 {
        attestations_v5: vec![],
        sync_contributions,
        attester_slashings_v5,
        proposer_slashings_v5,
        voluntary_exits_v5,
    };
    Ok(vec![v5.as_kv_store_op(OP_POOL_DB_KEY)])
}
