use crate::{
    ConsumerError, LightClientDataSource, SyncPolicy,
    sync::{check_response_size, checked_current_slot},
    updates::check_store_context,
};
use decentralized_checkpoint_sync::{
    LightClientStore, LightClientSyncError, VerifiedFinalizedHeader,
    process_light_client_finality_update, upgrade_light_client_store,
};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{ChainSpec, EthSpec, Hash256, Slot};

/// A verified processing step, not a promise of checkpoint advancement or freshness.
#[derive(Debug)]
pub struct ProcessedFinalityUpdate<E: EthSpec> {
    pub store: LightClientStore<E>,
    pub bytes_received: u64,
    /// Last local clock observation, for detecting regressions across consumer steps.
    pub observed_slot: Slot,
}

/// Fetch and process one finality update through the core's full verification path.
///
/// The caller supplies the same trusted context as for bootstrap/range processing. A finality
/// update cannot supply a missing sync committee; range catch-up remains a separate step.
/// A valid minority or stale update may not advance the authenticated checkpoint. Retain the
/// returned store and use [`recent_checkpoint_header`] when deciding whether to finish.
///
/// As with range processing, this consumes the store: failure/cancellation publishes no state,
/// and an already running blocking worker can only finish and drop its private result. There are
/// no retries or force updates here; the source must enforce the supplied request limits.
pub async fn process_finality_update<E: EthSpec>(
    source: &mut impl LightClientDataSource<E>,
    mut store: LightClientStore<E>,
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
    clock: &impl SlotClock,
    policy: &SyncPolicy,
) -> Result<ProcessedFinalityUpdate<E>, ConsumerError> {
    policy.validate()?;
    let started_slot = clock.now().ok_or(ConsumerError::ClockUnavailable)?;
    check_store_context(&store, started_slot, &spec)?;
    let runtime = tokio::runtime::Handle::try_current()?;

    let response = source.get_finality_update(policy.request_limits).await?;
    check_response_size(response.bytes_received, policy.request_limits)?;
    let current_slot = checked_current_slot(clock, started_slot)?;
    let current_fork = check_store_context(&store, current_slot, &spec)?;
    let bytes_received = response.bytes_received;
    let verification_spec = Arc::clone(&spec);
    let store = runtime
        .spawn_blocking(move || {
            upgrade_light_client_store(&mut store, current_fork)?;
            process_light_client_finality_update(
                &mut store,
                &response.data.data,
                response.data.data_fork,
                current_slot,
                genesis_validators_root,
                &verification_spec,
            )?;
            Ok::<_, LightClientSyncError>(store)
        })
        .await??;
    let returned_slot = checked_current_slot(clock, current_slot)?;
    check_store_context(&store, returned_slot, &spec)?;
    Ok(ProcessedFinalityUpdate {
        store,
        bytes_received,
        observed_slot: returned_slot,
    })
}

/// Select only an authenticated checkpoint that is recent at this local clock reading.
///
/// Call immediately before handing a checkpoint to the caller, also after bootstrap/range steps:
/// a sufficiently recent trusted bootstrap needs no additional finality update. `None` means
/// stale, not invalid; the store remains available for further synchronization. The provider's
/// reported head, optimistic header and spec finalized header never determine freshness.
///
/// This returns the core's existing authentication type, not an everlasting freshness guarantee.
/// Recheck after any further wait. The task driver must track clock regressions across steps;
/// this stateless check rejects a clock behind the store but cannot detect all past regressions.
pub fn recent_checkpoint_header<E: EthSpec>(
    store: &LightClientStore<E>,
    clock: &impl SlotClock,
    spec: &ChainSpec,
    policy: &SyncPolicy,
) -> Result<Option<VerifiedFinalizedHeader<E>>, ConsumerError> {
    policy.validate()?;
    let current_slot = clock.now().ok_or(ConsumerError::ClockUnavailable)?;
    recent_checkpoint_at_slot(store, current_slot, spec, policy)
}

/// The driver supplies its freshly sampled, regression-checked slot and already validated policy.
pub(crate) fn recent_checkpoint_at_slot<E: EthSpec>(
    store: &LightClientStore<E>,
    current_slot: Slot,
    spec: &ChainSpec,
    policy: &SyncPolicy,
) -> Result<Option<VerifiedFinalizedHeader<E>>, ConsumerError> {
    check_store_context(store, current_slot, spec)?;
    let checkpoint = store.verified_checkpoint_header();
    let age = current_slot
        .as_u64()
        .checked_sub(checkpoint.slot().as_u64())
        .ok_or(ConsumerError::FutureStore {
            store_slot: checkpoint.slot(),
            current_slot,
        })?;
    Ok((age <= policy.max_finalized_lag_slots).then(|| checkpoint.clone()))
}
