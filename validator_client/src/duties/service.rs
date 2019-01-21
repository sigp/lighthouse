use super::traits::BeaconNode;
use super::{DutiesManager, PollOutcome};
use slog::{debug, error, info, Logger};
use slot_clock::SlotClock;
use std::time::Duration;

pub struct DutiesManagerService<T: SlotClock, U: BeaconNode> {
    pub manager: DutiesManager<T, U>,
    pub poll_interval_millis: u64,
    pub log: Logger,
}

impl<T: SlotClock, U: BeaconNode> DutiesManagerService<T, U> {
    pub fn run(&mut self) {
        loop {
            match self.manager.poll() {
                Err(error) => {
                    error!(self.log, "Epoch duties poll error"; "error" => format!("{:?}", error))
                }
                Ok(PollOutcome::NoChange(epoch, _)) => {
                    debug!(self.log, "No change in duties"; "epoch" => epoch)
                }
                Ok(PollOutcome::DutiesChanged(epoch, duties)) => {
                    info!(self.log, "Duties changed (potential re-org)"; "epoch" => epoch, "duties" => format!("{:?}", duties))
                }
                Ok(PollOutcome::NewDuties(epoch, duties)) => {
                    info!(self.log, "New duties obtained"; "epoch" => epoch, "duties" => format!("{:?}", duties))
                }
                Ok(PollOutcome::UnknownValidatorOrEpoch(epoch)) => {
                    error!(self.log, "Epoch or validator unknown"; "epoch" => epoch)
                }
            };

            std::thread::sleep(Duration::from_millis(self.poll_interval_millis));
        }
    }
}
