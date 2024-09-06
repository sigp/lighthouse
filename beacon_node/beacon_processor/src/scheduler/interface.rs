use types::EthSpec;

use super::priority_scheduler;

pub enum SchedulerType<E: EthSpec> {
    PriorityScheduler(priority_scheduler::Scheduler<E>),
}

impl<E: EthSpec> SchedulerType<E> {
    // TODO(beacon-processor) make this config driven
    pub fn new() {}

    pub fn process_work_event(&self) {}
}
