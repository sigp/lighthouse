use crate::{
    LightClientStoreSchema, LightClientSyncError, ValidatedLightClientUpdate,
    VerifiedFinalizedHeader, beacon_header,
    update::{UpdateView, is_default_sync_committee, sync_committee_period},
    upgrade::{upgrade_light_client_header, upgrade_light_client_update},
};
use safe_arith::{ArithError, SafeArith};
use std::sync::Arc;
use types::{
    ChainSpec, EthSpec, ForkName, Hash256, LightClientHeader, LightClientUpdate, Slot,
    SyncCommittee,
};

/// Light-client state initialized by [`crate::initialize_light_client_store`].
///
/// Initialization and processing may retain older wire variants within a newer schema ceiling.
/// [`upgrade_light_client_store`] explicitly normalizes stored objects to a chosen data format.
/// The checkpoint header is tracked separately because the spec permits force updates to change
/// `finalized_header` without establishing supermajority finality.
#[derive(Debug)]
pub struct LightClientStore<E: EthSpec> {
    store_schema: LightClientStoreSchema,
    finalized_header: LightClientHeader<E>,
    optimistic_header: LightClientHeader<E>,
    current_sync_committee: Arc<SyncCommittee<E>>,
    next_sync_committee: Option<Arc<SyncCommittee<E>>>,
    // Separate from spec state: a committee learned through force update cannot authenticate
    // checkpoints, even if a subsequent signature has supermajority participation.
    current_sync_committee_authenticated: bool,
    next_sync_committee_authenticated: bool,
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
            current_sync_committee_authenticated: true,
            next_sync_committee_authenticated: false,
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
    ///
    /// Force updates never advance this anchor. Subsequent finality must be signed by a committee
    /// authenticated from the trusted bootstrap, not only one learned through a force update.
    pub fn verified_checkpoint_header(&self) -> &VerifiedFinalizedHeader<E> {
        &self.checkpoint_header
    }

    /// Seed a known committee for isolated validation tests.
    #[cfg(test)]
    pub(crate) fn set_next_sync_committee_for_test(&mut self, committee: Arc<SyncCommittee<E>>) {
        self.next_sync_committee = Some(committee);
        self.next_sync_committee_authenticated = false;
    }

    /// Apply spec state only, after the caller has checked the finalized period.
    /// Checkpoint authentication is deliberately handled separately by normal processing.
    fn apply_light_client_update(
        &mut self,
        finalized_header: &LightClientHeader<E>,
        next_sync_committee: &Arc<SyncCommittee<E>>,
        store_period: u64,
        finalized_period: u64,
        authenticate_next_committee: bool,
    ) {
        let next_committee =
            (!is_default_sync_committee(next_sync_committee)).then(|| next_sync_committee.clone());
        let next_authenticated = next_committee.is_some() && authenticate_next_committee;
        if let Some(current_next) = &self.next_sync_committee {
            if finalized_period.checked_sub(store_period) == Some(1) {
                self.current_sync_committee = current_next.clone();
                self.current_sync_committee_authenticated = self.next_sync_committee_authenticated;
                self.next_sync_committee = next_committee;
                self.next_sync_committee_authenticated = next_authenticated;
                self.previous_max_active_participants = self.current_max_active_participants;
                self.current_max_active_participants = 0;
            }
        } else {
            self.next_sync_committee = next_committee;
            self.next_sync_committee_authenticated = next_authenticated;
        }
        let finalized_slot = beacon_header(finalized_header).slot;
        if finalized_slot > beacon_header(&self.finalized_header).slot {
            self.finalized_header = finalized_header.clone();
            if finalized_slot > beacon_header(&self.optimistic_header).slot {
                self.optimistic_header = finalized_header.clone();
            }
        }
        self.best_valid_update = None;
    }
}

/// Upgrade the store's local data representations without advancing or authenticating its state.
///
/// Follows the Capella, Deneb and Electra light-client fork logic. This may be called before the
/// target fork activates. Fulu uses Electra's schema with distinct Rust object variants.
/// Committees, participation maxima and committee authentication flags remain unchanged.
/// The independent checkpoint keeps its beacon root and slot-derived fork, even after force updates.
///
/// All conversions finish before any store field changes. Unsupported targets and downgrades
/// leave the entire store unchanged. Same-schema calls still normalize older stored wire objects;
/// once all objects use the requested format, repeating the call is idempotent.
///
/// A pending validation token prevents upgrading its store before processing:
///
/// ```compile_fail,E0499
/// use decentralized_checkpoint_sync::{LightClientStore, validate_light_client_update,
///     upgrade_light_client_store};
/// use types::{ChainSpec, ForkName, Hash256, LightClientUpdate, MinimalEthSpec, Slot};
///
/// fn upgrade_while_pending(store: &mut LightClientStore<MinimalEthSpec>,
///     update: &LightClientUpdate<MinimalEthSpec>, spec: &ChainSpec) {
///     let pending = validate_light_client_update(store, update, ForkName::Altair,
///         Slot::new(10), Hash256::default(), spec);
///     let _ = upgrade_light_client_store(store, ForkName::Electra);
///     drop(pending);
/// }
/// ```
pub fn upgrade_light_client_store<E: EthSpec>(
    store: &mut LightClientStore<E>,
    target_fork: ForkName,
) -> Result<(), LightClientSyncError> {
    let requested = LightClientStoreSchema::try_from(target_fork)?;
    if requested < store.store_schema {
        return Err(LightClientSyncError::StoreSchemaDowngrade {
            current: store.store_schema,
            requested,
        });
    }
    let finalized_header = upgrade_light_client_header(&store.finalized_header, target_fork)?;
    let optimistic_header = upgrade_light_client_header(&store.optimistic_header, target_fork)?;
    let best_valid_update = store
        .best_valid_update
        .as_ref()
        .map(|update| upgrade_light_client_update(update, target_fork))
        .transpose()?;
    let checkpoint_header = store.checkpoint_header.upgrade(target_fork)?;

    store.finalized_header = finalized_header;
    store.optimistic_header = optimistic_header;
    store.best_valid_update = best_valid_update;
    store.checkpoint_header = checkpoint_header;
    store.store_schema = requested;
    Ok(())
}

/// Process an update already validated against its exclusively borrowed store.
///
/// Follows [consensus-specs v1.7.0-alpha.14 processing], including best-update selection,
/// optimistic tracking, and supermajority finality/committee rotation. The checkpoint anchor
/// advances only with a verified finality proof and supermajority from an authenticated committee.
/// This function does not force updates on timeout. All fallible work precedes store mutation.
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
    let signature_period = sync_committee_period::<E>(*update.signature_slot(), spec)?;
    let has_authenticated_supermajority = has_supermajority
        && if signature_period == store_period {
            store.current_sync_committee_authenticated
        } else {
            store.next_sync_committee_authenticated
        };
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

    // An independently authenticated proof can confirm a committee previously learned by force.
    // Do not let that committee authenticate itself via a next-period signature.
    if has_authenticated_supermajority
        && has_finality
        && has_next_committee
        && finalized_period == attested_period
        && attested_period == store_period
        && store.next_sync_committee.is_some()
    {
        store.next_sync_committee_authenticated = true;
    }
    if apply_update {
        // This update's participants have already been counted before a possible period reset.
        store.apply_light_client_update(
            &view.finalized_header,
            update.next_sync_committee(),
            store_period,
            finalized_period,
            has_authenticated_supermajority,
        );
    }

    // Do not confuse optimistic progress or a spec-level force update with checkpoint finality.
    if has_authenticated_supermajority
        && has_finality
        && finalized_slot > store.checkpoint_header.slot()
    {
        store.checkpoint_header = VerifiedFinalizedHeader::from_verified_finality(
            view.finalized_header,
            spec.fork_name_at_slot::<E>(finalized_slot),
        );
    }
    Ok(())
}

/// Apply the best validated update after strictly more than one committee period without finality.
///
/// This optional liveness fallback follows [consensus-specs v1.7.0-alpha.14 force update]. It may
/// promote the cached attested header into the spec's finalized field, but never into the verified
/// checkpoint. Committees newly learned here remain unauthenticated for checkpoint purposes.
/// A later supermajority from an unauthenticated committee cannot repair that trust chain; use an
/// independent proof from an authenticated committee or reinitialize from a trusted bootstrap.
///
/// `current_slot` must come from the local clock, and `spec` must be the same trusted configuration
/// used to validate updates. No cached update or an unexpired timeout leaves every field unchanged.
/// Errors also leave the store (including its cached best update) unchanged.
///
/// [consensus-specs v1.7.0-alpha.14 force update]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/altair/light-client/sync-protocol.md#process_light_client_store_force_update
pub fn process_light_client_store_force_update<E: EthSpec>(
    store: &mut LightClientStore<E>,
    current_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), LightClientSyncError> {
    let Some(best) = &store.best_valid_update else {
        return Ok(());
    };
    let store_slot = beacon_header(&store.finalized_header).slot;
    let store_period = sync_committee_period::<E>(store_slot, spec)?;
    let timeout = E::slots_per_epoch().safe_mul(spec.epochs_per_sync_committee_period.as_u64())?;
    // Comparing elapsed time avoids overflow in `store_slot + timeout` near u64::MAX.
    if current_slot
        .as_u64()
        .checked_sub(store_slot.as_u64())
        .is_none_or(|elapsed| elapsed <= timeout)
    {
        return Ok(());
    }

    let view = UpdateView::new(best);
    let finalized_header = if beacon_header(&view.finalized_header).slot > store_slot {
        view.finalized_header
    } else {
        view.attested_header
    };
    let finalized_period = sync_committee_period::<E>(beacon_header(&finalized_header).slot, spec)?;
    if store.next_sync_committee.is_none() && finalized_period != store_period {
        return Err(LightClientSyncError::InvalidFinalizedPeriod {
            store_period,
            finalized_period,
        });
    }
    let next_committee = best.next_sync_committee().clone();
    // Do not rewrite the cached update's proven finalized header into unproven attested data.
    // The effective header is passed separately and the cache is cleared only after application.
    store.apply_light_client_update(
        &finalized_header,
        &next_committee,
        store_period,
        finalized_period,
        false,
    );
    Ok(())
}
