use crate::{
    BootstrapError, LightClientDataSource, RequestLimits, SourceError, SourceErrorKind, SyncPolicy,
};
use decentralized_checkpoint_sync::{
    LightClientStore, LightClientStoreSchema, initialize_light_client_store,
};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{ChainSpec, EthSpec, Hash256, Slot};

/// A verified bootstrap store and its request accounting, not a completed synchronization.
#[derive(Debug)]
pub struct BootstrappedStore<E: EthSpec> {
    pub store: LightClientStore<E>,
    pub bytes_received: u64,
}

/// Fetch the exact trusted bootstrap and verify it using the transport-independent core.
///
/// The caller vouches for the root's finality and the network/clock configuration. This does not
/// establish freshness or fetch subsequent updates. There is one source request, with no retries;
/// the source enforces the supplied request limits. Task-wide retry/deadline orchestration belongs
/// to the later synchronization driver.
///
/// The store schema comes from the trusted schedule and local clock, never from response metadata.
/// The response's data fork is preserved for core verification, including upgraded historical
/// headers. All verification runs on the caller's Tokio blocking pool without shared live state.
/// Dropping this future cannot stop an already running blocking job, but its result is discarded:
/// no store is published or modified through a detached worker.
pub async fn bootstrap_light_client_store<E: EthSpec>(
    source: &mut impl LightClientDataSource<E>,
    trusted_block_root: Hash256,
    spec: Arc<ChainSpec>,
    clock: &impl SlotClock,
    policy: &SyncPolicy,
) -> Result<BootstrappedStore<E>, BootstrapError> {
    policy.validate()?;
    let started_slot = clock.now().ok_or(BootstrapError::ClockUnavailable)?;
    LightClientStoreSchema::try_from(spec.fork_name_at_slot::<E>(started_slot))?;
    let runtime = tokio::runtime::Handle::try_current()?;

    let response = source
        .get_bootstrap(trusted_block_root, policy.request_limits)
        .await?;
    let current_slot = checked_current_slot(clock, started_slot)?;
    // A fork may have activated while fetching. Re-evaluate only from local trusted context.
    let store_schema = LightClientStoreSchema::try_from(spec.fork_name_at_slot::<E>(current_slot))?;
    let bootstrap_slot = response.data.data.get_slot();
    if bootstrap_slot > current_slot {
        return Err(BootstrapError::FutureBootstrap {
            bootstrap_slot,
            current_slot,
        });
    }
    check_response_size(response.bytes_received, policy.request_limits)?;
    let bytes_received = response.bytes_received;
    let store = runtime
        .spawn_blocking(move || {
            initialize_light_client_store(
                trusted_block_root,
                &response.data.data,
                response.data.data_fork,
                store_schema,
                &spec,
            )
        })
        .await??;
    checked_current_slot(clock, current_slot)?;
    Ok(BootstrappedStore {
        store,
        bytes_received,
    })
}

pub(crate) fn checked_current_slot(
    clock: &impl SlotClock,
    previous: Slot,
) -> Result<Slot, BootstrapError> {
    let current = clock.now().ok_or(BootstrapError::ClockUnavailable)?;
    if current < previous {
        return Err(BootstrapError::ClockWentBackwards { previous, current });
    }
    Ok(current)
}

pub(crate) fn check_response_size(
    bytes_received: u64,
    limits: RequestLimits,
) -> Result<(), SourceError> {
    if bytes_received > limits.max_response_bytes() {
        return Err(SourceError {
            kind: SourceErrorKind::ResponseTooLarge {
                limit: limits.max_response_bytes(),
            },
            bytes_received,
            source: None,
        });
    }
    Ok(())
}
