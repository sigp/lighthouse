use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
};

use types::EthSpec;

use crate::{Work, WorkEvent};

pub struct WorkQueue<E: EthSpec> {
    min_heap: BinaryHeap<Reverse<QueueItem<E>>>,
}

pub struct QueueItem<E: EthSpec> {
    deadline: u64,
    pub work_event: WorkEvent<E>,
}

impl<E: EthSpec> QueueItem<E> {
    pub fn new(work: Work<E>) -> Self {
        let work_event = WorkEvent {
            drop_during_sync: false,
            work,
        };

        Self {
            work_event,
            deadline: 0,
        }
    }
}

impl<E: EthSpec> std::cmp::Eq for QueueItem<E> {}

impl<E: EthSpec> PartialEq for QueueItem<E> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl<E: EthSpec> PartialOrd for QueueItem<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.deadline.partial_cmp(&other.deadline)
    }
}

impl<E: EthSpec> Ord for QueueItem<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline.cmp(&other.deadline)
    }
}

impl<E: EthSpec> WorkQueue<E> {
    pub fn new() -> Self {
        WorkQueue {
            min_heap: BinaryHeap::new(),
        }
    }

    pub fn insert(&mut self, queue_item: QueueItem<E>) {
        self.min_heap.push(Reverse(queue_item))
    }

    pub fn pop(&mut self) -> Option<QueueItem<E>> {
        if let Some(queue_item) = self.min_heap.pop() {
            Some(queue_item.0)
        } else {
            None
        }
    }

    fn peek(&self) -> Option<&Reverse<QueueItem<E>>> {
        self.min_heap.peek()
    }
}
