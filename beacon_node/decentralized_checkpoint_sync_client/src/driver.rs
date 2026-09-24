use crate::{
    ConsumerError, LightClientDataSource, SyncBudget, SyncError, SyncPolicy,
    bootstrap_light_client_store, finality::recent_checkpoint_at_slot,
    managed_source::ManagedSource, process_finality_update, process_next_update_range,
    updates::period,
};
use decentralized_checkpoint_sync::{VerifiedFinalizedHeader, beacon_header};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::time::{Instant, timeout_at};
use types::{ChainSpec, EthSpec, Hash256};

/// Cumulative task usage, including transient failures and retry attempts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncUsage {
    pub requests: u64,
    /// Decoded range/finality updates, including unsuccessful verification. Bootstrap is separate.
    pub updates: u64,
    /// Charged body bytes. If our timeout drops a source before it can report partial bytes,
    /// conservatively charge that request's full byte allowance instead of undercounting it.
    pub response_bytes: u64,
}

#[derive(Debug)]
pub struct SyncOutcome<E: EthSpec> {
    pub header: VerifiedFinalizedHeader<E>,
    pub usage: SyncUsage,
}

/// Obtain a recent authenticated checkpoint from an untrusted source, within explicit limits.
///
/// Trust inputs are the finalized bootstrap root, network specification/genesis validators root
/// and local clock. This reuses the same bootstrap/range/finality verification as individual steps;
/// it never force-updates or accepts a caller-supplied store with an unknown trust history.
/// Only transient source failures are retried, with capped exponential backoff and Retry-After.
/// Unavailable, malformed and cryptographically invalid inputs remain distinct terminal errors.
///
/// The caller supplies a Tokio runtime with its time driver enabled. The deadline covers all I/O,
/// verification waits and sleeps. Dropping this future cancels I/O/backoff and schedules no further
/// requests. An already running blocking verifier may finish but owns only private, discarded state.
/// Freshness is checked at handoff; callers must recheck it if they delay using the returned header.
pub async fn sync_verified_finalized_header<E: EthSpec>(
    source: &mut impl LightClientDataSource<E>,
    trusted_block_root: Hash256,
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
    clock: &impl SlotClock,
    policy: &SyncPolicy,
) -> Result<SyncOutcome<E>, SyncError> {
    policy.validate().map_err(ConsumerError::from)?;
    tokio::runtime::Handle::try_current().map_err(ConsumerError::from)?;
    let deadline = Instant::from_std(
        policy
            .deadline(Instant::now().into_std())
            .map_err(ConsumerError::from)?,
    );
    let mut source = ManagedSource::new(source, clock, policy, deadline)?;
    let task = async {
        let bootstrap = bootstrap_light_client_store(
            &mut source,
            trusted_block_root,
            spec.clone(),
            clock,
            policy,
        )
        .await;
        let bootstrap = source.finish_step(bootstrap)?;
        source.observe_slot(bootstrap.observed_slot)?;
        let mut store = bootstrap.store;
        source.reset_progress();

        loop {
            let current_slot = source.observe_clock()?;
            if let Some(header) = recent_checkpoint_at_slot(&store, current_slot, &spec, policy)? {
                source.check_deadline()?;
                return Ok(SyncOutcome {
                    header,
                    usage: source.usage,
                });
            }
            let remaining_updates = policy.max_updates.saturating_sub(source.usage.updates);
            if remaining_updates == 0 {
                return Err(SyncError::BudgetExceeded {
                    resource: SyncBudget::Updates,
                    limit: policy.max_updates,
                });
            }
            let checkpoint_before = store.verified_checkpoint_header().slot();
            let next_known_before = store.next_sync_committee().is_some();
            let store_period =
                period::<E>(beacon_header(store.spec_finalized_header()).slot, &spec)?;
            let current_period = period::<E>(current_slot, &spec)?;
            // Finality needs the current signing committee, not knowledge of its successor.
            let can_verify_current_period = store_period == current_period
                || (next_known_before && current_period.checked_sub(store_period) == Some(1));
            if can_verify_current_period {
                let result = process_finality_update(
                    &mut source,
                    store,
                    spec.clone(),
                    genesis_validators_root,
                    clock,
                    policy,
                )
                .await;
                let result = source.finish_step(result)?;
                source.observe_slot(result.observed_slot)?;
                store = result.store;
            } else {
                let mut step_policy = policy.clone();
                step_policy.max_updates_per_request =
                    step_policy.max_updates_per_request.min(remaining_updates);
                let result = process_next_update_range(
                    &mut source,
                    store,
                    spec.clone(),
                    genesis_validators_root,
                    clock,
                    &step_policy,
                )
                .await;
                let result = source.finish_step(result)?;
                source.observe_slot(result.observed_slot)?;
                store = result.store;
            }
            // By induction from bootstrap, all committees in this private, never-forced store
            // are authenticated. Rotation also advances the checkpoint; optimistic/best-update
            // and participation changes alone do not count as progress.
            let progressed = store.verified_checkpoint_header().slot() > checkpoint_before
                || (!next_known_before && store.next_sync_committee().is_some());
            if progressed {
                source.reset_progress();
            } else {
                source.check_no_progress()?;
                source.sleep(policy.initial_retry_delay).await?;
            }
        }
    };
    match timeout_at(deadline, task).await {
        Ok(result) => {
            // A ready future can complete without timeout_at observing its elapsed deadline.
            if result.is_ok() {
                source.check_deadline()?;
            }
            result
        }
        Err(_) => Err(SyncError::DeadlineExceeded),
    }
}
