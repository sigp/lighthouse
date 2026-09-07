use crate::{LightClientStoreSchema, VerifiedFinalizedHeader};
use std::sync::Arc;
use types::{EthSpec, LightClientHeader, LightClientUpdate, SyncCommittee};

/// Light-client state initialized by [`crate::initialize_light_client_store`].
///
/// Headers retain their original Rust enum variants when a newer store schema is selected.
/// Validation uses their beacon slots and data schemas, without eagerly upgrading SSZ objects.
/// The checkpoint header is tracked separately because the spec permits force updates to change
/// `finalized_header` without establishing supermajority finality.
#[derive(Debug)]
pub struct LightClientStore<E: EthSpec> {
    store_schema: LightClientStoreSchema,
    finalized_header: LightClientHeader<E>,
    optimistic_header: LightClientHeader<E>,
    current_sync_committee: Arc<SyncCommittee<E>>,
    next_sync_committee: Option<Arc<SyncCommittee<E>>>,
    best_valid_update: Option<LightClientUpdate<E>>,
    previous_max_active_participants: u64,
    current_max_active_participants: u64,
    checkpoint_header: VerifiedFinalizedHeader<E>,
}

impl<E: EthSpec> LightClientStore<E> {
    pub(crate) fn from_bootstrap(
        checkpoint_header: VerifiedFinalizedHeader<E>,
        current_sync_committee: Arc<SyncCommittee<E>>,
        store_schema: LightClientStoreSchema,
    ) -> Self {
        Self {
            store_schema,
            finalized_header: checkpoint_header.header().clone(),
            optimistic_header: checkpoint_header.header().clone(),
            current_sync_committee,
            next_sync_committee: None,
            best_valid_update: None,
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
            checkpoint_header,
        }
    }

    pub fn store_schema(&self) -> LightClientStoreSchema {
        self.store_schema
    }

    /// The spec's finalized header, which is not sufficient to authenticate a checkpoint.
    pub fn spec_finalized_header(&self) -> &LightClientHeader<E> {
        &self.finalized_header
    }

    pub fn optimistic_header(&self) -> &LightClientHeader<E> {
        &self.optimistic_header
    }

    pub fn current_sync_committee(&self) -> &SyncCommittee<E> {
        &self.current_sync_committee
    }

    /// `None` represents the spec's empty (unknown) next sync committee.
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee<E>> {
        self.next_sync_committee.as_deref()
    }

    pub fn best_valid_update(&self) -> Option<&LightClientUpdate<E>> {
        self.best_valid_update.as_ref()
    }

    pub fn previous_max_active_participants(&self) -> u64 {
        self.previous_max_active_participants
    }

    pub fn current_max_active_participants(&self) -> u64 {
        self.current_max_active_participants
    }

    /// The header eligible to anchor checkpoint snapshot proofs.
    pub fn verified_checkpoint_header(&self) -> &VerifiedFinalizedHeader<E> {
        &self.checkpoint_header
    }

    /// Seed the next-period validation path before update processing is implemented.
    #[cfg(test)]
    pub(crate) fn set_next_sync_committee_for_test(&mut self, committee: Arc<SyncCommittee<E>>) {
        self.next_sync_committee = Some(committee);
    }
}
