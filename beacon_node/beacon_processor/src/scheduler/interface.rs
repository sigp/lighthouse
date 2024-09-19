// use tokio::sync::mpsc;
// use types::EthSpec;

// use crate::WorkEvent;

// use super::priority_scheduler;

// pub enum SchedulerType<E: EthSpec> {
//     PriorityScheduler(priority_scheduler::Scheduler<E>),
// }

// impl<E: EthSpec> SchedulerType<E> {
//     // TODO(beacon-processor) make this config driven
//     pub fn run(
//         &self, 
//         event_rx: mpsc::Receiver<WorkEvent<E>>,
//         work_journal_tx: Option<mpsc::Sender<&'static str>>,
//     ) {

//     }

//     pub fn process_work_event(&self) {}
// }
