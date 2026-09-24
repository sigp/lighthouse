use crate::{
    ConsumerError, LightClientData, LightClientDataSource, SyncPolicy, UpdateRange,
    UpdateRangeError,
    sync::{check_response_size, checked_current_slot},
};
use decentralized_checkpoint_sync::{
    LightClientStore, LightClientStoreSchema, LightClientSyncError, beacon_header,
    process_light_client_update, upgrade_light_client_store, validate_light_client_update,
};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{ChainSpec, EthSpec, ForkName, Hash256, LightClientUpdate, Slot};

/// A single range step, not a claim of coverage, authenticated committee progress or freshness.
#[derive(Debug)]
pub struct ProcessedUpdateRange<E: EthSpec> {
    pub store: LightClientStore<E>,
    /// `None` means no range was requested: the store already knows the local current committee
    /// and its successor. A finality request may still be needed to obtain a recent checkpoint.
    pub range: Option<UpdateRange>,
    pub updates_processed: u64,
    pub bytes_received: u64,
    /// Last local clock observation, for detecting regressions across consumer steps.
    pub observed_slot: Slot,
}

/// Plan from processed store state, never from a response length or provider-reported head.
///
/// Request the store's period until it knows the next committee, then request the next period.
/// Always cap the range at the local current period and the supplied per-request limit.
/// `None` does not establish checkpoint eligibility, including for stores advanced by force.
pub fn next_update_range<E: EthSpec>(
    store: &LightClientStore<E>,
    current_slot: Slot,
    spec: &ChainSpec,
    max_updates: u64,
) -> Result<Option<UpdateRange>, ConsumerError> {
    UpdateRange::new(0, max_updates)?;
    check_store_context(store, current_slot, spec)?;
    let current_period = period::<E>(current_slot, spec)?;
    let store_slot = beacon_header(store.spec_finalized_header()).slot;
    let store_period = period::<E>(store_slot, spec)?;
    let known_next = u64::from(store.next_sync_committee().is_some());
    let start = store_period
        .checked_add(known_next)
        .ok_or(crate::PolicyError::RangeOverflow {
            start_period: store_period,
            count: known_next,
        })?;
    if start > current_period {
        return Ok(None);
    }
    let available = current_period
        .checked_sub(start)
        .and_then(|distance| distance.checked_add(1))
        .ok_or(crate::PolicyError::RangeOverflow {
            start_period: start,
            count: max_updates,
        })?;
    Ok(Some(UpdateRange::new(start, available.min(max_updates))?))
}

/// Fetch and process at most one bounded range. No retries, force updates or freshness decision.
///
/// The caller must retain the bootstrap's trusted spec, genesis validators root and clock.
/// Short/empty pages do not advance a request cursor: re-plan from the returned store. Successful
/// processing can change only optimistic/best-update state without authenticating any checkpoint.
///
/// This takes exclusive ownership of the store. A failed or cancelled step drops it; no partially
/// processed page or detached mutation of caller-owned state is published. Whole-task retry
/// scheduling belongs around the source request, before handing the store to the blocking worker.
pub async fn process_next_update_range<E: EthSpec>(
    source: &mut impl LightClientDataSource<E>,
    mut store: LightClientStore<E>,
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
    clock: &impl SlotClock,
    policy: &SyncPolicy,
) -> Result<ProcessedUpdateRange<E>, ConsumerError> {
    policy.validate()?;
    let started_slot = clock.now().ok_or(ConsumerError::ClockUnavailable)?;
    let range = next_update_range(&store, started_slot, &spec, policy.max_updates_per_request)?;
    let Some(range) = range else {
        return Ok(ProcessedUpdateRange {
            store,
            range: None,
            updates_processed: 0,
            bytes_received: 0,
            observed_slot: started_slot,
        });
    };
    let runtime = tokio::runtime::Handle::try_current()?;
    let response = source.get_updates(range, policy.request_limits).await?;
    check_response_size(response.bytes_received, policy.request_limits)?;
    let current_slot = checked_current_slot(clock, started_slot)?;
    let current_fork = spec.fork_name_at_slot::<E>(current_slot);
    LightClientStoreSchema::try_from(current_fork)?;
    let updates_processed = check_page(&response.data, range, &spec)?;
    let bytes_received = response.bytes_received;
    if updates_processed != 0 {
        store = runtime
            .spawn_blocking(move || {
                // Upgrade only to the trusted local fork, not to a provider-selected schema.
                upgrade_light_client_store(&mut store, current_fork)?;
                for update in response.data {
                    let validated = validate_light_client_update(
                        &mut store,
                        &update.data,
                        update.data_fork,
                        current_slot,
                        genesis_validators_root,
                        &spec,
                    )?;
                    process_light_client_update(validated)?;
                }
                Ok::<_, LightClientSyncError>(store)
            })
            .await??;
    }
    let observed_slot = checked_current_slot(clock, current_slot)?;
    Ok(ProcessedUpdateRange {
        store,
        range: Some(range),
        updates_processed,
        bytes_received,
        observed_slot,
    })
}

pub(crate) fn period<E: EthSpec>(slot: Slot, spec: &ChainSpec) -> Result<u64, ConsumerError> {
    slot.as_u64()
        .checked_div(E::slots_per_epoch())
        .and_then(|epoch| epoch.checked_div(spec.epochs_per_sync_committee_period.as_u64()))
        .ok_or(ConsumerError::InvalidPeriodConfiguration)
}

/// Shared preflight for store-based steps and checkpoint selection. This does not upgrade state.
pub(crate) fn check_store_context<E: EthSpec>(
    store: &LightClientStore<E>,
    current_slot: Slot,
    spec: &ChainSpec,
) -> Result<ForkName, ConsumerError> {
    // Check divisors before fork lookup, which assumes a non-zero slots-per-epoch configuration.
    period::<E>(current_slot, spec)?;
    let fork = spec.fork_name_at_slot::<E>(current_slot);
    let current_schema = LightClientStoreSchema::try_from(fork)?;
    if current_schema < store.store_schema() {
        return Err(LightClientSyncError::StoreSchemaDowngrade {
            current: store.store_schema(),
            requested: current_schema,
        }
        .into());
    }
    let store_slot = beacon_header(store.spec_finalized_header()).slot;
    if store_slot > current_slot {
        return Err(ConsumerError::FutureStore {
            store_slot,
            current_slot,
        });
    }
    Ok(fork)
}

fn check_page<E: EthSpec>(
    updates: &[LightClientData<LightClientUpdate<E>>],
    range: UpdateRange,
    spec: &ChainSpec,
) -> Result<u64, ConsumerError> {
    let too_many = || UpdateRangeError::TooManyUpdates {
        actual: updates.len(),
        maximum: range.count(),
    };
    let count = u64::try_from(updates.len()).map_err(|_| too_many())?;
    if count > range.count() {
        return Err(too_many().into());
    }
    // Check the entire envelope before expensive verification; never sort or silently skip data.
    for (update, expected) in updates.iter().zip(range.start_period()..range.end_period()) {
        let actual = period::<E>(update.data.attested_header_slot(), spec)?;
        if actual < range.start_period() || actual >= range.end_period() {
            return Err(UpdateRangeError::OutsideRange {
                period: actual,
                start: range.start_period(),
                end: range.end_period(),
            }
            .into());
        }
        if actual != expected {
            return Err(if expected == range.start_period() {
                UpdateRangeError::MissingStartPeriod { expected, actual }
            } else {
                UpdateRangeError::NonConsecutivePeriods { expected, actual }
            }
            .into());
        }
    }
    Ok(count)
}
