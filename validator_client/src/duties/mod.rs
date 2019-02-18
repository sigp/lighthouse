mod epoch_duties;
mod grpc;
mod service;
#[cfg(test)]
mod test_node;
mod traits;

pub use self::epoch_duties::EpochDutiesMap;
use self::epoch_duties::{EpochDuties, EpochDutiesMapError};
pub use self::service::DutiesManagerService;
use self::traits::{BeaconNode, BeaconNodeError};
use bls::PublicKey;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{ChainSpec, Epoch};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PollOutcome {
    /// The `EpochDuties` were not updated during this poll.
    NoChange(Epoch),
    /// The `EpochDuties` for the `epoch` were previously unknown, but obtained in the poll.
    NewDuties(Epoch, EpochDuties),
    /// New `EpochDuties` were obtained, different to those which were previously known. This is
    /// likely to be the result of chain re-organisation.
    DutiesChanged(Epoch, EpochDuties),
    /// The Beacon Node was unable to return the duties as the validator is unknown, or the
    /// shuffling for the epoch is unknown.
    UnknownValidatorOrEpoch(Epoch),
}

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotClockError,
    SlotUnknowable,
    EpochMapPoisoned,
    BeaconNodeError(BeaconNodeError),
}

/// A polling state machine which ensures the latest `EpochDuties` are obtained from the Beacon
/// Node.
///
/// There is a single `DutiesManager` per validator instance.
pub struct DutiesManager<T: SlotClock, U: BeaconNode> {
    pub duties_map: Arc<EpochDutiesMap>,
    /// The validator's public key.
    pub pubkey: PublicKey,
    pub spec: Arc<ChainSpec>,
    pub slot_clock: Arc<T>,
    pub beacon_node: Arc<U>,
}

impl<T: SlotClock, U: BeaconNode> DutiesManager<T, U> {
    /// Poll the Beacon Node for `EpochDuties`.
    ///
    /// The present `epoch` will be learned from the supplied `SlotClock`. In production this will
    /// be a wall-clock (e.g., system time, remote server time, etc.).
    pub fn poll(&self) -> Result<PollOutcome, Error> {
        let slot = self
            .slot_clock
            .present_slot()
            .map_err(|_| Error::SlotClockError)?
            .ok_or(Error::SlotUnknowable)?;

        let epoch = slot.epoch(self.spec.epoch_length);

        if let Some(duties) = self.beacon_node.request_shuffling(epoch, &self.pubkey)? {
            // If these duties were known, check to see if they're updates or identical.
            let result = if let Some(known_duties) = self.duties_map.get(epoch)? {
                if known_duties == duties {
                    Ok(PollOutcome::NoChange(epoch))
                } else {
                    Ok(PollOutcome::DutiesChanged(epoch, duties))
                }
            } else {
                Ok(PollOutcome::NewDuties(epoch, duties))
            };
            self.duties_map.insert(epoch, duties)?;
            result
        } else {
            Ok(PollOutcome::UnknownValidatorOrEpoch(epoch))
        }
    }
}

impl From<BeaconNodeError> for Error {
    fn from(e: BeaconNodeError) -> Error {
        Error::BeaconNodeError(e)
    }
}

impl From<EpochDutiesMapError> for Error {
    fn from(e: EpochDutiesMapError) -> Error {
        match e {
            EpochDutiesMapError::Poisoned => Error::EpochMapPoisoned,
        }
    }
}

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
        let duties_map = Arc::new(EpochDutiesMap::new(spec.epoch_length));
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
