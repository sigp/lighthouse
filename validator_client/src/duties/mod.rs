mod epoch_duties;
mod grpc;
// TODO: reintroduce tests
//#[cfg(test)]
//mod test_node;
mod traits;

use self::epoch_duties::{EpochDuties, EpochDutiesMapError};
pub use self::epoch_duties::{EpochDutiesMap, WorkInfo};
use self::traits::{BeaconNode, BeaconNodeError};
use futures::Async;
use slog::{debug, error, info};
use std::sync::Arc;
use std::sync::RwLock;
use types::{Epoch, Keypair, Slot};

#[derive(Debug, PartialEq, Clone)]
pub enum UpdateOutcome {
    /// The `EpochDuties` were not updated during this poll.
    NoChange(Epoch),
    /// The `EpochDuties` for the `epoch` were previously unknown, but obtained in the poll.
    NewDuties(Epoch, EpochDuties),
    /// New `EpochDuties` were obtained, different to those which were previously known. This is
    /// likely to be the result of chain re-organisation.
    DutiesChanged(Epoch, EpochDuties),
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DutiesMapPoisoned,
    EpochMapPoisoned,
    BeaconNodeError(BeaconNodeError),
    UnknownEpoch,
    UnknownValidator,
}

/// A polling state machine which ensures the latest `EpochDuties` are obtained from the Beacon
/// Node.
///
/// This keeps track of all validator keys and required voting slots.
pub struct DutiesManager<U: BeaconNode> {
    pub duties_map: RwLock<EpochDutiesMap>,
    /// A list of all signer objects known to the validator service.
    // TODO: Generalise the signers, so that they're not just keypairs
    pub signers: Arc<Vec<Keypair>>,
    pub beacon_node: Arc<U>,
}

impl<U: BeaconNode> DutiesManager<U> {
    /// Check the Beacon Node for `EpochDuties`.
    ///
    /// be a wall-clock (e.g., system time, remote server time, etc.).
    fn update(&self, epoch: Epoch) -> Result<UpdateOutcome, Error> {
        let duties = self.beacon_node.request_duties(epoch, &self.signers)?;
        {
            // If these duties were known, check to see if they're updates or identical.
            if let Some(known_duties) = self.duties_map.read()?.get(&epoch) {
                if *known_duties == duties {
                    return Ok(UpdateOutcome::NoChange(epoch));
                }
            }
        }
        if !self.duties_map.read()?.contains_key(&epoch) {
            //TODO: Remove clone by removing duties from outcome
            self.duties_map.write()?.insert(epoch, duties.clone());
            return Ok(UpdateOutcome::NewDuties(epoch, duties));
        }
        // duties have changed
        //TODO: Duties could be large here. Remove from display and avoid the clone.
        self.duties_map.write()?.insert(epoch, duties.clone());
        return Ok(UpdateOutcome::DutiesChanged(epoch, duties));
    }

    /// A future wrapping around `update()`. This will perform logic based upon the update
    /// process and complete once the update has completed.
    pub fn run_update(&self, epoch: Epoch, log: slog::Logger) -> Result<Async<()>, ()> {
        match self.update(epoch) {
            Err(error) => error!(log, "Epoch duties poll error"; "error" => format!("{:?}", error)),
            Ok(UpdateOutcome::NoChange(epoch)) => {
                debug!(log, "No change in duties"; "epoch" => epoch)
            }
            Ok(UpdateOutcome::DutiesChanged(epoch, duties)) => {
                info!(log, "Duties changed (potential re-org)"; "epoch" => epoch, "duties" => format!("{:?}", duties))
            }
            Ok(UpdateOutcome::NewDuties(epoch, duties)) => {
                info!(log, "New duties obtained"; "epoch" => epoch, "duties" => format!("{:?}", duties))
            }
        };
        Ok(Async::Ready(()))
    }

    /// Returns a list of (Public, WorkInfo) indicating all the validators that have work to perform
    /// this slot.
    pub fn get_current_work(&self, slot: Slot) -> Option<Vec<(Keypair, WorkInfo)>> {
        let mut current_work: Vec<(Keypair, WorkInfo)> = Vec::new();

        // if the map is poisoned, return None
        let duties = self.duties_map.read().ok()?;

        for validator_signer in self.signers.iter() {
            match duties.is_work_slot(slot, &validator_signer) {
                Ok(Some(work_type)) => current_work.push((validator_signer.clone(), work_type)),
                Ok(None) => {} // No work for this validator
                //TODO: This should really log an error, as we shouldn't end up with an err here.
                Err(_) => {}   // Unknown epoch or validator, no work
            }
        }
        if current_work.is_empty() {
            return None;
        }
        Some(current_work)
    }
}

//TODO: Use error_chain to handle errors
impl From<BeaconNodeError> for Error {
    fn from(e: BeaconNodeError) -> Error {
        Error::BeaconNodeError(e)
    }
}

//TODO: Use error_chain to handle errors
impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_e: std::sync::PoisonError<T>) -> Error {
        Error::DutiesMapPoisoned
    }
}
impl From<EpochDutiesMapError> for Error {
    fn from(e: EpochDutiesMapError) -> Error {
        match e {
            EpochDutiesMapError::Poisoned => Error::EpochMapPoisoned,
            EpochDutiesMapError::UnknownEpoch => Error::UnknownEpoch,
            EpochDutiesMapError::UnknownValidator => Error::UnknownValidator,
        }
    }
}

/* TODO: Modify tests for new Duties Manager form
#[cfg(test)]
mod tests {
    use super::test_node::TestBeaconNode;
    use super::*;
    use bls::Keypair;
    use slot_clock::TestingSlotClock;
    use types::Slot;

    // TODO: implement more thorough testing.
    // https://github.com/sigp/lighthouse/issues/160
    //
    // These tests should serve as a good example for future tests.


    #[test]
    pub fn polling() {
        let spec = Arc::new(ChainSpec::foundation());
        let duties_map = Arc::new(EpochDutiesMap::new(spec.slots_per_epoch));
        let keypair = Keypair::random();
        let slot_clock = Arc::new(TestingSlotClock::new(0));
        let beacon_node = Arc::new(TestBeaconNode::default());

        let manager = DutiesManager {
            spec: spec.clone(),
            pubkey: keypair.pk.clone(),
            duties_map: duties_map.clone(),
            slot_clock: slot_clock.clone(),
            beacon_node: beacon_node.clone(),
        };

        // Configure response from the BeaconNode.
        let duties = EpochDuties {
            validator_index: 0,
            block_production_slot: Some(Slot::new(10)),
        };
        beacon_node.set_next_shuffling_result(Ok(Some(duties)));

        // Get the duties for the first time...
        assert_eq!(
            manager.poll(),
            Ok(PollOutcome::NewDuties(Epoch::new(0), duties))
        );
        // Get the same duties again...
        assert_eq!(manager.poll(), Ok(PollOutcome::NoChange(Epoch::new(0))));

        // Return new duties.
        let duties = EpochDuties {
            validator_index: 0,
            block_production_slot: Some(Slot::new(11)),
        };
        beacon_node.set_next_shuffling_result(Ok(Some(duties)));
        assert_eq!(
            manager.poll(),
            Ok(PollOutcome::DutiesChanged(Epoch::new(0), duties))
        );

        // Return no duties.
        beacon_node.set_next_shuffling_result(Ok(None));
        assert_eq!(
            manager.poll(),
            Ok(PollOutcome::UnknownValidatorOrEpoch(Epoch::new(0)))
        );
    }
}
*/
