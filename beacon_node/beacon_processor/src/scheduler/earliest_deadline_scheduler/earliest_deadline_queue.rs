use std::{
    cmp::{max, Reverse},
    collections::BinaryHeap,
    marker::PhantomData,
    time::Duration,
};

use slot_clock::SlotClock;
use types::{EthSpec, Slot};

use crate::{ReprocessQueueMessage, Work, WorkEvent};

pub struct WorkQueue<Q: std::cmp::Ord> {
    min_heap: BinaryHeap<Reverse<Q>>,
}

pub struct QueueItem<E: EthSpec, S: SlotClock> {
    deadline: Duration,
    pub work_event: WorkEvent<E>,
    phantom_data: PhantomData<S>,
}

impl<E: EthSpec, S: SlotClock> QueueItem<E, S> {
    pub fn new(work_event: WorkEvent<E>, slot_clock: &S) -> Option<Self> {
        let Some(deadline) = QueueItem::calculate_deadline(&work_event.work, slot_clock) else {
            return None;
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
        println!("work: {:?}", work);
        let deadline = match work {
            Work::GossipAttestation { attestation, .. } => {
                let attestation_slot = attestation.attestation.data().slot;
                Self::calculate_unaggregated_attestation_deadline(attestation_slot, slot_clock)
            }
            Work::GossipAttestationToConvert { attestation, .. } => {
                let attestation_slot = attestation.attestation.data.slot;
                Self::calculate_unaggregated_attestation_deadline(attestation_slot, slot_clock)
            }
            Work::GossipAttestationBatch { attestations, .. } => {
                let Some(attestation) = attestations.first() else {
                    return None;
                };
                let attestation_slot = attestation.attestation.data().slot;
                Self::calculate_unaggregated_attestation_deadline(attestation_slot, slot_clock)
            }
            Work::GossipAggregate { aggregate, .. } => {
                let attestation_slot = aggregate.aggregate.message().aggregate().data().slot;
                Self::calculate_aggregate_attestation_deadline(attestation_slot, slot_clock)
            }
            Work::GossipAggregateBatch { aggregates, .. } => {
                let Some(aggregate) = aggregates.first() else {
                    return None;
                };

                let attestation_slot = aggregate.aggregate.message().aggregate().data().slot;
                Self::calculate_aggregate_attestation_deadline(attestation_slot, slot_clock)
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
            | Work::RpcVerifyDataColumn { .. }
            | Work::SamplingResult(_)
            | Work::BlocksByRangeRequest(_)
            | Work::BlocksByRootsRequest(_)
            | Work::BlobsByRangeRequest(_)
            | Work::BlobsByRootsRequest(_)
            | Work::DataColumnsByRootsRequest(_)
            | Work::DataColumnsByRangeRequest(_)
            | Work::GossipBlsToExecutionChange(_) => {
                Some(current_time.saturating_add(Duration::from_secs(1)))
            }
            Work::UnknownLightClientOptimisticUpdate { .. }
            | Work::GossipVoluntaryExit(_)
            | Work::GossipLightClientFinalityUpdate(_)
            | Work::GossipLightClientOptimisticUpdate(_)
            | Work::Status(_)
            | Work::LightClientBootstrapRequest(_)
            | Work::LightClientOptimisticUpdateRequest(_)
            | Work::LightClientFinalityUpdateRequest(_)
            | Work::LightClientUpdatesByRangeRequest(_)
            | Work::ApiRequestP0(_)
            | Work::ApiRequestP1(_) => Some(current_time.saturating_add(Duration::from_secs(4))),
            Work::RpcBlock { .. }
            | Work::IgnoredRpcBlock { .. }
            | Work::ChainSegment(_)
            | Work::ChainSegmentBackfill(_)
            | Work::UnknownBlockAggregate { .. }
            | Work::GossipBlock(_)
            | Work::DelayedImportBlock { .. } => Some(current_time),
            Work::Reprocess(reprocess_queue_message) => {
                Self::calculate_reprocess_deadline(reprocess_queue_message, slot_clock)
            }
            Work::GossipCanonicalBlock(_) | Work::RpcCanonicalBlock { .. } => {
                Some(Duration::from_secs(0))
            }
        };

        println!("deadline {:?}", deadline);

        deadline
    }

    /// An unaggregated attestation should be scheduled to be processed no later than within four seconds of the start of the current slot
    /// or within a second of its arrival time if received later than the four second deadline.
    fn calculate_unaggregated_attestation_deadline(
        attestation_slot: Slot,
        slot_clock: &S,
    ) -> Option<Duration> {
        let Some(current_time) = slot_clock.now_duration() else {
            return None;
        };

        let Some(start_of_attestation_slot) = slot_clock.start_of(attestation_slot) else {
            return None;
        };

        let four_seconds_into_slot =
            start_of_attestation_slot.saturating_add(Duration::from_secs(4));

        let arrival_time_with_buffer = current_time.saturating_add(Duration::from_secs(1));
        Some(max(four_seconds_into_slot, arrival_time_with_buffer))
    }

    /// An aggregation attestation should be scheduled to be processed no later than the start of the next slot
    /// or within a second of its arrival time if received later than the start of the next slot.
    fn calculate_aggregate_attestation_deadline(
        attestation_slot: Slot,
        slot_clock: &S,
    ) -> Option<Duration> {
        let Some(current_time) = slot_clock.now_duration() else {
            return None;
        };

        let Some(start_of_next_slot) = slot_clock.start_of(attestation_slot + Slot::new(1)) else {
            return None;
        };
        let arrival_time_with_buffer = current_time.saturating_add(Duration::from_secs(1));

        Some(max(start_of_next_slot, arrival_time_with_buffer))
    }

    fn calculate_reprocess_deadline(
        reprocess_queue_message: &ReprocessQueueMessage,
        slot_clock: &S,
    ) -> Option<Duration> {
        let Some(current_time) = slot_clock.now_duration() else {
            return None;
        };

        println!("reprocessing");

        match reprocess_queue_message {
            ReprocessQueueMessage::EarlyBlock(_)
            | ReprocessQueueMessage::RpcBlock(_)
            | ReprocessQueueMessage::BlockImported { .. }
            | ReprocessQueueMessage::UnknownBlockUnaggregate(_)
            | ReprocessQueueMessage::UnknownBlockAggregate(_) => Some(current_time),
            ReprocessQueueMessage::NewLightClientOptimisticUpdate { .. }
            | ReprocessQueueMessage::UnknownLightClientOptimisticUpdate(_)
            | ReprocessQueueMessage::UnknownBlockSamplingRequest(_) => {
                Some(current_time.saturating_add(Duration::from_secs(1)))
            }
            ReprocessQueueMessage::BackfillSync(_) => {
                Some(current_time.saturating_add(Duration::from_secs(4)))
            }
        }
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
        Some(self.cmp(other))
    }
}

impl<E: EthSpec, S: SlotClock> Ord for QueueItem<E, S> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

impl<Q: std::cmp::Ord> WorkQueue<Q> {
    pub fn new() -> Self {
        WorkQueue {
            min_heap: BinaryHeap::new(),
        }
    }

    pub fn insert(&mut self, queue_item: Q) {
        self.min_heap.push(Reverse(queue_item))
    }

    pub fn pop(&mut self) -> Option<Q> {
        if let Some(queue_item) = self.min_heap.pop() {
            Some(queue_item.0)
        } else {
            None
        }
    }

    fn _peek(&self) -> Option<&Reverse<Q>> {
        self.min_heap.peek()
    }

    pub fn len(&self) -> usize {
        self.min_heap.len()
    }

    // TODO do we want an is_full method? should there be a concept of full?
    pub fn _is_full(&self) -> bool {
        todo!()
    }
}
