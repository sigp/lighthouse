use slog::trace;
use tokio::sync::mpsc::Sender;
use types::EthSpec;

use crate::metrics;
use crate::{BeaconProcessor, BlockingOrAsync, SendOnDrop, TaskSpawner, Work};

mod earliest_deadline_scheduler;
pub mod interface;
mod priority_scheduler;

/// Spawns a blocking worker thread to process some `Work`.
///
/// Sends an message on `idle_tx` when the work is complete and the task is stopping.
pub fn spawn_worker<E: EthSpec>(
    beacon_processor: &mut BeaconProcessor<E>,
    idle_tx: Sender<()>,
    work: Work<E>,
) {
    let work_id = work.str_id();
    let worker_timer = metrics::start_timer_vec(&metrics::BEACON_PROCESSOR_WORKER_TIME, &[work_id]);
    metrics::inc_counter(&metrics::BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL);
    metrics::inc_counter_vec(
        &metrics::BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT,
        &[work.str_id()],
    );

    // Wrap the `idle_tx` in a struct that will fire the idle message whenever it is dropped.
    //
    // This helps ensure that the worker is always freed in the case of an early exit or panic.
    // As such, this instantiation should happen as early in the function as possible.
    let send_idle_on_drop = SendOnDrop {
        tx: idle_tx,
        _worker_timer: worker_timer,
        log: beacon_processor.log.clone(),
    };

    let worker_id = beacon_processor.current_workers;
    beacon_processor.current_workers = beacon_processor.current_workers.saturating_add(1);

    let executor = beacon_processor.executor.clone();

    trace!(
        beacon_processor.log,
        "Spawning beacon processor worker";
        "work" => work_id,
        "worker" => worker_id,
    );

    let task_spawner = TaskSpawner {
        executor,
        send_idle_on_drop,
    };

    match work {
        Work::GossipAttestation {
            attestation,
            process_individual,
            process_batch: _,
        } => task_spawner.spawn_blocking(move || {
            process_individual(*attestation);
        }),
        Work::GossipAttestationBatch {
            attestations,
            process_batch,
        } => task_spawner.spawn_blocking(move || {
            process_batch(attestations);
        }),
        Work::GossipAggregate {
            aggregate,
            process_individual,
            process_batch: _,
        } => task_spawner.spawn_blocking(move || {
            process_individual(*aggregate);
        }),
        Work::GossipAggregateBatch {
            aggregates,
            process_batch,
        } => task_spawner.spawn_blocking(move || {
            process_batch(aggregates);
        }),
        Work::ChainSegment(process_fn) => task_spawner.spawn_async(async move {
            process_fn.await;
        }),
        Work::UnknownBlockAttestation { process_fn }
        | Work::UnknownBlockAggregate { process_fn }
        | Work::UnknownLightClientOptimisticUpdate { process_fn, .. }
        | Work::UnknownBlockSamplingRequest { process_fn } => {
            task_spawner.spawn_blocking(process_fn)
        }
        Work::DelayedImportBlock {
            beacon_block_slot: _,
            beacon_block_root: _,
            process_fn,
        } => task_spawner.spawn_async(process_fn),
        Work::RpcBlock { process_fn }
        | Work::RpcBlobs { process_fn }
        | Work::RpcCustodyColumn(process_fn)
        | Work::RpcVerifyDataColumn(process_fn)
        | Work::SamplingResult(process_fn) => task_spawner.spawn_async(process_fn),
        Work::IgnoredRpcBlock { process_fn } => task_spawner.spawn_blocking(process_fn),
        Work::GossipBlock(work)
        | Work::GossipBlobSidecar(work)
        | Work::GossipDataColumnSidecar(work) => task_spawner.spawn_async(async move {
            work.await;
        }),
        Work::BlobsByRangeRequest(process_fn)
        | Work::BlobsByRootsRequest(process_fn)
        | Work::DataColumnsByRootsRequest(process_fn)
        | Work::DataColumnsByRangeRequest(process_fn) => task_spawner.spawn_blocking(process_fn),
        Work::BlocksByRangeRequest(work) | Work::BlocksByRootsRequest(work) => {
            task_spawner.spawn_async(work)
        }
        Work::ChainSegmentBackfill(process_fn) => task_spawner.spawn_async(process_fn),
        Work::ApiRequestP0(process_fn) | Work::ApiRequestP1(process_fn) => match process_fn {
            BlockingOrAsync::Blocking(process_fn) => task_spawner.spawn_blocking(process_fn),
            BlockingOrAsync::Async(process_fn) => task_spawner.spawn_async(process_fn),
        },
        Work::GossipVoluntaryExit(process_fn)
        | Work::GossipProposerSlashing(process_fn)
        | Work::GossipAttesterSlashing(process_fn)
        | Work::GossipSyncSignature(process_fn)
        | Work::GossipSyncContribution(process_fn)
        | Work::GossipLightClientFinalityUpdate(process_fn)
        | Work::GossipLightClientOptimisticUpdate(process_fn)
        | Work::Status(process_fn)
        | Work::GossipBlsToExecutionChange(process_fn)
        | Work::LightClientBootstrapRequest(process_fn)
        | Work::LightClientOptimisticUpdateRequest(process_fn)
        | Work::LightClientFinalityUpdateRequest(process_fn)
        | Work::LightClientUpdatesByRangeRequest(process_fn) => {
            task_spawner.spawn_blocking(process_fn)
        }
        Work::Reprocess(_) => (),
    };
}
