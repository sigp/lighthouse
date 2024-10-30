use std::{
    cmp::{max, Reverse},
    collections::BinaryHeap,
    marker::PhantomData,
    time::Duration,
};

use slot_clock::SlotClock;
use types::{EthSpec, Slot};

use crate::{Work, WorkEvent};

pub struct WorkQueue<E: EthSpec, S: SlotClock> {
    min_heap: BinaryHeap<Reverse<QueueItem<E, S>>>,
}

pub struct QueueItem<E: EthSpec, S: SlotClock> {
    deadline: Duration,
    pub work_event: WorkEvent<E>,
    phantom_data: PhantomData<S>,
}

impl<E: EthSpec, S: SlotClock> QueueItem<E, S> {
    pub fn new(work: Work<E>, slot_clock: &S) -> Option<Self> {
        let Some(deadline) = QueueItem::calculate_deadline(&work, slot_clock) else {
            return None;
        };

        let work_event = WorkEvent {
            drop_during_sync: false,
            work,
        };

        Some(Self {
            work_event,
            deadline,
            phantom_data: PhantomData,
        })
    }

    fn calculate_deadline(work: &Work<E>, slot_clock: &S) -> Option<Duration> {
        let Some(current_time) = slot_clock.now_duration() else {
            return None;
        };
        let deadline = match work {
            Work::GossipAttestation { attestation, .. } => {
                let attestation_slot = attestation.attestation.data().slot;

                let Some(start_of_attestation_slot) = slot_clock.start_of(attestation_slot) else {
                    return None;
                };

                let arrival_time_with_buffer = current_time.saturating_add(Duration::from_secs(1));
                let four_seconds_into_slot =
                    start_of_attestation_slot.saturating_add(Duration::from_secs(4));
                Some(max(four_seconds_into_slot, arrival_time_with_buffer))
            }
            Work::GossipAttestationBatch { attestations, .. } => {
                let Some(attestation) = attestations.first() else {
                    return None;
                };

                let attestation_slot = attestation.attestation.data().slot;

                let Some(start_of_attestation_slot) = slot_clock.start_of(attestation_slot) else {
                    return None;
                };

                let four_seconds_into_slot =
                    start_of_attestation_slot.saturating_add(Duration::from_secs(4));

                let arrival_time_with_buffer = current_time.saturating_add(Duration::from_secs(1));
                Some(max(four_seconds_into_slot, arrival_time_with_buffer))
            }
            Work::GossipAggregate { aggregate, .. } => {
                let attestation_slot = aggregate.aggregate.message().aggregate().data().slot;
                let Some(start_of_next_slot) = slot_clock.start_of(attestation_slot + Slot::new(1))
                else {
                    return None;
                };
                let arrival_time_with_buffer = current_time.saturating_add(Duration::from_secs(1));

                Some(max(start_of_next_slot, arrival_time_with_buffer))
            }
            Work::UnknownBlockAggregate { .. } => Some(current_time),
            Work::GossipAggregateBatch { aggregates, .. } => {
                let Some(aggregate) = aggregates.first() else {
                    return None;
                };

                let attestation_slot = aggregate.aggregate.message().aggregate().data().slot;
                let Some(start_of_next_slot) = slot_clock.start_of(attestation_slot + Slot::new(1))
                else {
                    return None;
                };
                let arrival_time_with_buffer = current_time.saturating_add(Duration::from_secs(1));

                Some(max(start_of_next_slot, arrival_time_with_buffer))
            }
            Work::GossipBlock(_) => Some(current_time),
            Work::DelayedImportBlock { .. } => Some(current_time),
            Work::GossipVoluntaryExit(_) => {
                Some(current_time.saturating_add(Duration::from_secs(4)))
            }
            Work::UnknownLightClientOptimisticUpdate { .. } => {
                Some(current_time.saturating_add(Duration::from_secs(4)))
            }
            Work::UnknownBlockAttestation { .. }
            | Work::UnknownBlockSamplingRequest { .. }
            | Work::GossipBlobSidecar(_)
            | Work::GossipDataColumnSidecar(_)
            | Work::GossipProposerSlashing(_)
            | Work::GossipAttesterSlashing(_)
            | Work::GossipSyncSignature(_)
            | Work::GossipSyncContribution(_)
            | Work::RpcBlobs { .. }
            | Work::RpcCustodyColumn { .. }
            | Work::RpcVerifyDataColumn { .. } => {
                Some(current_time.saturating_add(Duration::from_secs(1)))
            }
            Work::GossipLightClientFinalityUpdate(..) => {
                Some(current_time.saturating_add(Duration::from_secs(4)))
            }
            Work::GossipLightClientOptimisticUpdate(fn_once) => todo!(),
            Work::RpcBlock { process_fn } => todo!(),
            (pin) => todo!(),
            (pin) => todo!(),
            Work::SamplingResult(pin) => todo!(),
            Work::IgnoredRpcBlock { process_fn } => todo!(),
            Work::ChainSegment(pin) => todo!(),
            Work::ChainSegmentBackfill(pin) => todo!(),
            Work::Status(fn_once) => todo!(),
            Work::BlocksByRangeRequest(pin) => todo!(),
            Work::BlocksByRootsRequest(pin) => todo!(),
            Work::BlobsByRangeRequest(fn_once) => todo!(),
            Work::BlobsByRootsRequest(fn_once) => todo!(),
            Work::DataColumnsByRootsRequest(fn_once) => todo!(),
            Work::DataColumnsByRangeRequest(fn_once) => todo!(),
            Work::GossipBlsToExecutionChange(fn_once) => todo!(),
            Work::LightClientBootstrapRequest(fn_once) => todo!(),
            Work::LightClientOptimisticUpdateRequest(fn_once) => todo!(),
            Work::LightClientFinalityUpdateRequest(fn_once) => todo!(),
            Work::LightClientUpdatesByRangeRequest(fn_once) => todo!(),
            Work::ApiRequestP0(blocking_or_async) => todo!(),
            Work::ApiRequestP1(blocking_or_async) => todo!(),
            Work::Reprocess(reprocess_queue_message) => todo!(),
        };

        deadline
    }
}

impl<E: EthSpec, S: SlotClock> std::cmp::Eq for QueueItem<E, S> {}

impl<E: EthSpec, S: SlotClock> PartialEq for QueueItem<E, S> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl<E: EthSpec, S: SlotClock> PartialOrd for QueueItem<E, S> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.deadline.partial_cmp(&other.deadline)
    }
}

impl<E: EthSpec, S: SlotClock> Ord for QueueItem<E, S> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

impl<E: EthSpec, S: SlotClock> WorkQueue<E, S> {
    pub fn new() -> Self {
        WorkQueue {
            min_heap: BinaryHeap::new(),
        }
    }

    pub fn insert(&mut self, queue_item: QueueItem<E, S>) {
        self.min_heap.push(Reverse(queue_item))
    }

    pub fn pop(&mut self) -> Option<QueueItem<E, S>> {
        if let Some(queue_item) = self.min_heap.pop() {
            Some(queue_item.0)
        } else {
            None
        }
    }

    fn peek(&self) -> Option<&Reverse<QueueItem<E, S>>> {
        self.min_heap.peek()
    }

    pub fn len(&self) -> usize {
        self.min_heap.len()
    }

    // TODO do we want an is_full method? should there be a concept of full?
    pub fn is_full(&self) -> bool {
        todo!()
    }
}
