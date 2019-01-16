use super::traits::{BeaconNode, BeaconNodeError};
use super::{DutiesManager, PollOutcome};
use slog::{debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use std::time::Duration;

pub struct DutiesService<T: SlotClock, U: BeaconNode> {
    pub manager: DutiesManager<T, U>,
    pub poll_interval_millis: u64,
    pub log: Logger,
}

impl<T: SlotClock, U: BeaconNode> DutiesService<T, U> {
    pub fn run(&mut self) {
        loop {
            match self.manager.poll() {
                Err(error) => {
                    error!(self.log, "Epoch duties poll error"; "error" => format!("{:?}", error))
                }
                Ok(PollOutcome::NoChange) => debug!(self.log, "No change in duties"),
                Ok(PollOutcome::DutiesChanged) => {
                    info!(self.log, "Duties changed (potential re-org)")
                }
                Ok(PollOutcome::NewDuties) => info!(self.log, "New duties obtained"),
                Ok(PollOutcome::UnknownValidatorOrEpoch) => {
                    error!(self.log, "Epoch or validator unknown")
                }
            };

            std::thread::sleep(Duration::from_millis(self.poll_interval_millis));
        }
    }
}
