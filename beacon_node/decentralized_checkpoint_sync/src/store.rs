use crate::{
    LightClientStoreSchema, LightClientSyncError, ValidatedLightClientUpdate,
    VerifiedFinalizedHeader, beacon_header,
    update::{UpdateView, is_default_sync_committee, sync_committee_period},
};
use safe_arith::{ArithError, SafeArith};
use std::sync::Arc;
use types::{EthSpec, Hash256, LightClientHeader, LightClientUpdate, SyncCommittee};

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

    /// Optimistic updates require strictly more participants than this threshold.
    pub fn safety_threshold(&self) -> u64 {
        self.previous_max_active_participants
            .max(self.current_max_active_participants)
            / 2
    }

    /// The header eligible to anchor checkpoint snapshot proofs.
    pub fn verified_checkpoint_header(&self) -> &VerifiedFinalizedHeader<E> {
        &self.checkpoint_header
    }

    /// Seed a known committee for isolated validation tests.
    #[cfg(test)]
    pub(crate) fn set_next_sync_committee_for_test(&mut self, committee: Arc<SyncCommittee<E>>) {
        self.next_sync_committee = Some(committee);
    }
}

/// Process an update already validated against its exclusively borrowed store.
///
/// Follows [consensus-specs v1.7.0-alpha.14 processing], including best-update selection,
/// optimistic tracking, and supermajority finality/committee rotation. The checkpoint anchor
/// advances only with a verified finality proof and supermajority participation. This function
/// does not implement timeout-based force updates. All fallible work precedes store mutation.
///
/// [consensus-specs v1.7.0-alpha.14 processing]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/altair/light-client/sync-protocol.md#process_light_client_update
///
/// A validation token can be consumed only once:
///
/// ```compile_fail,E0382
/// use decentralized_checkpoint_sync::{ValidatedLightClientUpdate, process_light_client_update};
/// use types::MinimalEthSpec;
///
/// fn apply_twice(validated: ValidatedLightClientUpdate<'_, '_, MinimalEthSpec>) {
///     let _ = process_light_client_update(validated);
///     let _ = process_light_client_update(validated);
/// }
/// ```
pub fn process_light_client_update<E: EthSpec>(
    validated: ValidatedLightClientUpdate<'_, '_, E>,
) -> Result<(), LightClientSyncError> {
    let (store, update, spec) = validated.into_parts();
    let view = UpdateView::new(update);
    let attested_slot = beacon_header(&view.attested_header).slot;
    let finalized_slot = beacon_header(&view.finalized_header).slot;
    let store_slot = beacon_header(&store.finalized_header).slot;
    let store_period = sync_committee_period::<E>(store_slot, spec)?;
    let attested_period = sync_committee_period::<E>(attested_slot, spec)?;
    let finalized_period = sync_committee_period::<E>(finalized_slot, spec)?;
    let participants =
        u64::try_from(update.sync_aggregate().num_set_bits()).map_err(|_| ArithError::Overflow)?;
    let committee_size = u64::try_from(update.sync_aggregate().sync_committee_bits.len())
        .map_err(|_| ArithError::Overflow)?;
    let has_supermajority = participants.safe_mul(3)? >= committee_size.safe_mul(2)?;
    let has_finality = view
        .finality_branch
        .iter()
        .any(|node| *node != Hash256::default());
    // Unlike the types helper used for ranking, presence does not depend on signature period.
    let has_next_committee = view
        .next_committee_branch
        .iter()
        .any(|node| *node != Hash256::default());
    let has_finalized_next_committee = store.next_sync_committee.is_none()
        && has_next_committee
        && has_finality
        && finalized_period == attested_period;
    let apply_update =
        has_supermajority && (finalized_slot > store_slot || has_finalized_next_committee);
    if apply_update && store.next_sync_committee.is_none() && finalized_period != store_period {
        return Err(LightClientSyncError::InvalidFinalizedPeriod {
            store_period,
            finalized_period,
        });
    }
    let replace_best = match &store.best_valid_update {
        None => true,
        // The receiver is the OLD update; the argument is the NEW candidate.
        Some(best) => best
            .is_better_light_client_update(update, spec)
            .map_err(|error| LightClientSyncError::UpdateRankingFailed(format!("{error:?}")))?,
    };

    if replace_best {
        store.best_valid_update = Some(update.clone());
    }
    store.current_max_active_participants = store.current_max_active_participants.max(participants);
    if participants > store.safety_threshold()
        && attested_slot > beacon_header(&store.optimistic_header).slot
    {
        store.optimistic_header = view.attested_header;
    }

    if apply_update {
        // An absent/default committee stays unknown, including when rotating with finality only.
        let next_committee = (!is_default_sync_committee(update.next_sync_committee()))
            .then(|| update.next_sync_committee().clone());
        if let Some(current_next) = &store.next_sync_committee {
            if finalized_period.checked_sub(store_period) == Some(1) {
                store.current_sync_committee = current_next.clone();
                store.next_sync_committee = next_committee;
                // Include this update's participants before resetting the new period's maximum.
                store.previous_max_active_participants = store.current_max_active_participants;
                store.current_max_active_participants = 0;
            }
        } else {
            store.next_sync_committee = next_committee;
        }
        if finalized_slot > store_slot {
            store.finalized_header = view.finalized_header.clone();
            if finalized_slot > beacon_header(&store.optimistic_header).slot {
                store.optimistic_header = view.finalized_header.clone();
            }
        }
        store.best_valid_update = None;
    }

    // Do not confuse optimistic progress or a spec-level force update with checkpoint finality.
    if has_supermajority && has_finality && finalized_slot > store.checkpoint_header.slot() {
        store.checkpoint_header = VerifiedFinalizedHeader::from_verified_finality(
            view.finalized_header,
            spec.fork_name_at_slot::<E>(finalized_slot),
        );
    }
    Ok(())
}
