mod epoch_duties;
mod grpc;
#[cfg(test)]
mod test_node;
mod traits;

pub use self::epoch_duties::EpochDutiesMap;
use self::epoch_duties::{EpochDuties, EpochDutiesMapError};
use self::traits::{BeaconNode, BeaconNodeError};
use bls::PublicKey;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{ChainSpec, Epoch, Slot};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum UpdateOutcome {
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
/// This keeps track of all validator keys and required voting slots.
pub struct DutiesManager<T: SlotClock, U: BeaconNode> {
    pub duties_map: Arc<EpochDutiesMap>,
    /// A list of all public keys known to the validator service.
    pub pubkeys: Vec<PublicKey>,
    pub spec: Arc<ChainSpec>,
    pub slot_clock: Arc<T>,
    pub beacon_node: Arc<U>,
}

impl<T: SlotClock, U: BeaconNode> DutiesManager<T, U> {
    /// Check the Beacon Node for `EpochDuties`.
    ///
    /// The present `epoch` will be learned from the supplied `SlotClock`. In production this will
    /// be a wall-clock (e.g., system time, remote server time, etc.).
    pub fn update(&self, slot: Slot) -> Result<UpdateOutcome, Error> {
        let epoch = slot.epoch(self.spec.slots_per_epoch);

        if let Some(duties) = self
            .beacon_node
            .request_shuffling(epoch, &self.pubkeys[0])?
        {
            // If these duties were known, check to see if they're updates or identical.
            let result = if let Some(known_duties) = self.duties_map.get(epoch)? {
                if known_duties == duties {
                    Ok(UpdateOutcome::NoChange(epoch))
                } else {
                    Ok(UpdateOutcome::DutiesChanged(epoch, duties))
                }
            } else {
                Ok(UpdateOutcome::NewDuties(epoch, duties))
            };
            self.duties_map.insert(epoch, duties)?;
            result
        } else {
            Ok(UpdateOutcome::UnknownValidatorOrEpoch(epoch))
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
