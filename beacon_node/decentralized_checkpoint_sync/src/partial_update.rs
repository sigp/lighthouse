use crate::{
    LightClientStore, LightClientSyncError, process_light_client_update,
    validate_light_client_update,
};
use std::sync::Arc;
use types::{
    ChainSpec, EthSpec, ForkName, Hash256, LightClientFinalityUpdate, LightClientOptimisticUpdate,
    LightClientUpdate, LightClientUpdateAltair, LightClientUpdateCapella, LightClientUpdateDeneb,
    LightClientUpdateElectra, LightClientUpdateFulu, Slot, SyncCommittee,
};

/// Validate and process a finality update using the full update verification path.
///
/// Missing committee fields are filled with spec defaults, never with the store's committee.
/// `data_fork`, `current_slot`, `genesis_validators_root` and `spec` have the same requirements
/// as [`validate_light_client_update`]. An error leaves the store unchanged.
///
/// Implements [consensus-specs v1.7.0-alpha.14 finality update processing].
///
/// [consensus-specs v1.7.0-alpha.14 finality update processing]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/altair/light-client/sync-protocol.md#process_light_client_finality_update
pub fn process_light_client_finality_update<E: EthSpec>(
    store: &mut LightClientStore<E>,
    update: &LightClientFinalityUpdate<E>,
    data_fork: ForkName,
    current_slot: Slot,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<(), LightClientSyncError> {
    macro_rules! full_update {
        ($inner:ident, $variant:ident, $type:ident) => {
            LightClientUpdate::$variant($type {
                attested_header: $inner.attested_header.clone(),
                finalized_header: $inner.finalized_header.clone(),
                finality_branch: $inner.finality_branch.clone(),
                next_sync_committee: Arc::new(SyncCommittee::temporary()),
                next_sync_committee_branch: Default::default(),
                sync_aggregate: $inner.sync_aggregate.clone(),
                signature_slot: $inner.signature_slot,
            })
        };
    }
    let full_update = match update {
        LightClientFinalityUpdate::Altair(inner) => {
            full_update!(inner, Altair, LightClientUpdateAltair)
        }
        LightClientFinalityUpdate::Capella(inner) => {
            full_update!(inner, Capella, LightClientUpdateCapella)
        }
        LightClientFinalityUpdate::Deneb(inner) => {
            full_update!(inner, Deneb, LightClientUpdateDeneb)
        }
        LightClientFinalityUpdate::Electra(inner) => {
            full_update!(inner, Electra, LightClientUpdateElectra)
        }
        LightClientFinalityUpdate::Fulu(inner) => full_update!(inner, Fulu, LightClientUpdateFulu),
    };
    validate_light_client_update(
        store,
        &full_update,
        data_fork,
        current_slot,
        genesis_validators_root,
        spec,
    )
    .and_then(process_light_client_update)
}

/// Validate and process an optimistic update using the full update verification path.
///
/// Finality and committee fields are filled with spec defaults. Even a full-participation
/// optimistic update cannot authenticate a checkpoint or supply a next committee.
/// Caller context has the same requirements as [`validate_light_client_update`].
/// An error leaves the store unchanged.
///
/// Implements [consensus-specs v1.7.0-alpha.14 optimistic update processing].
///
/// [consensus-specs v1.7.0-alpha.14 optimistic update processing]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/altair/light-client/sync-protocol.md#process_light_client_optimistic_update
pub fn process_light_client_optimistic_update<E: EthSpec>(
    store: &mut LightClientStore<E>,
    update: &LightClientOptimisticUpdate<E>,
    data_fork: ForkName,
    current_slot: Slot,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<(), LightClientSyncError> {
    macro_rules! full_update {
        ($inner:ident, $variant:ident, $type:ident) => {
            LightClientUpdate::$variant($type {
                attested_header: $inner.attested_header.clone(),
                finalized_header: Default::default(),
                finality_branch: Default::default(),
                next_sync_committee: Arc::new(SyncCommittee::temporary()),
                next_sync_committee_branch: Default::default(),
                sync_aggregate: $inner.sync_aggregate.clone(),
                signature_slot: $inner.signature_slot,
            })
        };
    }
    let full_update = match update {
        LightClientOptimisticUpdate::Altair(inner) => {
            full_update!(inner, Altair, LightClientUpdateAltair)
        }
        LightClientOptimisticUpdate::Capella(inner) => {
            full_update!(inner, Capella, LightClientUpdateCapella)
        }
        LightClientOptimisticUpdate::Deneb(inner) => {
            full_update!(inner, Deneb, LightClientUpdateDeneb)
        }
        LightClientOptimisticUpdate::Electra(inner) => {
            full_update!(inner, Electra, LightClientUpdateElectra)
        }
        LightClientOptimisticUpdate::Fulu(inner) => {
            full_update!(inner, Fulu, LightClientUpdateFulu)
        }
    };
    validate_light_client_update(
        store,
        &full_update,
        data_fork,
        current_slot,
        genesis_validators_root,
        spec,
    )
    .and_then(process_light_client_update)
}
