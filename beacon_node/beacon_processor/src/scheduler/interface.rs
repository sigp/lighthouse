use std::time::Duration;

use slot_clock::SlotClock;
use tokio::sync::mpsc;
use types::EthSpec;

use crate::WorkEvent;

use super::priority_scheduler;

pub trait Scheduler<E: EthSpec, S: SlotClock> {
    fn run(
        &self, 
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
    );
}

pub enum SchedulerType<E: EthSpec, S: SlotClock> {
    PriorityScheduler(priority_scheduler::Scheduler<E, S>),
}

impl<E: EthSpec, S: SlotClock + 'static> Scheduler<E, S> for SchedulerType<E, S> {
    // TODO(beacon-processor) make this config driven
    fn run(
        &self, 
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
    ) {
        todo!()
    }
}
