use std::time::Duration;

use slot_clock::SlotClock;
use tokio::sync::mpsc;
use types::{BeaconState, ChainSpec, EthSpec};

use crate::{BeaconProcessor, WorkEvent};

use super::priority_scheduler;

pub trait Scheduler<E: EthSpec, S: SlotClock> {
    fn new(
        beacon_processor: BeaconProcessor<E>,
        beacon_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Box<Self>, String>;

    fn run(
        self,
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
    ) -> Result<(), String>;
}

pub enum SchedulerType<E: EthSpec, S: SlotClock> {
    PriorityScheduler(priority_scheduler::Scheduler<E, S>),
}

impl<E: EthSpec, S: SlotClock + 'static> Scheduler<E, S> for SchedulerType<E, S> {
    fn new(
        beacon_processor: BeaconProcessor<E>,
        beacon_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Box<Self>, String> {
        Ok(Box::new(SchedulerType::PriorityScheduler(
            priority_scheduler::Scheduler::new(beacon_processor, beacon_state, spec)?,
        )))
    }
    // TODO(beacon-processor) make this config driven
    fn run(
        self,
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
    ) -> Result<(), String> {
        match self {
            SchedulerType::PriorityScheduler(scheduler) => scheduler.run(
                event_rx,
                work_journal_tx,
                slot_clock,
                maximum_gossip_clock_disparity,
            ),
        }
    }
}
