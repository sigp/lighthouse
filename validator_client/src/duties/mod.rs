mod grpc;
mod service;
#[cfg(test)]
mod test_node;
mod traits;

use self::traits::{BeaconNode, BeaconNodeError};
use bls::PublicKey;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use types::ChainSpec;

pub use self::service::DutiesManagerService;

/// The information required for a validator to propose and attest during some epoch.
///
/// Generally obtained from a Beacon Node, this information contains the validators canonical index
/// (thier sequence in the global validator induction process) and the "shuffling" for that index
/// for some epoch.
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub struct EpochDuties {
    pub validator_index: u64,
    pub block_production_slot: Option<u64>,
    // Future shard info
}

impl EpochDuties {
    /// Returns `true` if the supplied `slot` is a slot in which the validator should produce a
    /// block.
    pub fn is_block_production_slot(&self, slot: u64) -> bool {
        match self.block_production_slot {
            Some(s) if s == slot => true,
            _ => false,
        }
    }
}

/// Maps an `epoch` to some `EpochDuties` for a single validator.
pub type EpochDutiesMap = HashMap<u64, EpochDuties>;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PollOutcome {
    /// The `EpochDuties` were not updated during this poll.
    NoChange(u64),
    /// The `EpochDuties` for the `epoch` were previously unknown, but obtained in the poll.
    NewDuties(u64, EpochDuties),
    /// New `EpochDuties` were obtained, different to those which were previously known. This is
    /// likely to be the result of chain re-organisation.
    DutiesChanged(u64, EpochDuties),
    /// The Beacon Node was unable to return the duties as the validator is unknown, or the
    /// shuffling for the epoch is unknown.
    UnknownValidatorOrEpoch(u64),
}

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotClockError,
    SlotUnknowable,
    EpochMapPoisoned,
    SlotClockPoisoned,
    EpochLengthIsZero,
    BeaconNodeError(BeaconNodeError),
}

/// A polling state machine which ensures the latest `EpochDuties` are obtained from the Beacon
/// Node.
///
/// There is a single `DutiesManager` per validator instance.
pub struct DutiesManager<T: SlotClock, U: BeaconNode> {
    pub duties_map: Arc<RwLock<EpochDutiesMap>>,
    /// The validator's public key.
    pub pubkey: PublicKey,
    pub spec: Arc<ChainSpec>,
    pub slot_clock: Arc<RwLock<T>>,
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
            .read()
            .map_err(|_| Error::SlotClockPoisoned)?
            .present_slot()
            .map_err(|_| Error::SlotClockError)?
            .ok_or(Error::SlotUnknowable)?;

        let epoch = slot
            .checked_div(self.spec.epoch_length)
            .ok_or(Error::EpochLengthIsZero)?;

        if let Some(duties) = self.beacon_node.request_shuffling(epoch, &self.pubkey)? {
            let mut map = self
                .duties_map
                .write()
                .map_err(|_| Error::EpochMapPoisoned)?;

            // If these duties were known, check to see if they're updates or identical.
            let result = if let Some(known_duties) = map.get(&epoch) {
                if *known_duties == duties {
                    Ok(PollOutcome::NoChange(epoch))
                } else {
                    Ok(PollOutcome::DutiesChanged(epoch, duties))
                }
            } else {
                Ok(PollOutcome::NewDuties(epoch, duties))
            };
            map.insert(epoch, duties);
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

#[cfg(test)]
mod tests {
    use super::test_node::TestBeaconNode;
    use super::*;
    use bls::Keypair;
    use slot_clock::TestingSlotClock;

    // TODO: implement more thorough testing.
    // https://github.com/sigp/lighthouse/issues/160
    //
    // These tests should serve as a good example for future tests.

    #[test]
    pub fn polling() {
        let spec = Arc::new(ChainSpec::foundation());
        let duties_map = Arc::new(RwLock::new(EpochDutiesMap::new()));
        let keypair = Keypair::random();
        let slot_clock = Arc::new(RwLock::new(TestingSlotClock::new(0)));
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
            block_production_slot: Some(10),
        };
        beacon_node.set_next_shuffling_result(Ok(Some(duties)));

        // Get the duties for the first time...
        assert_eq!(manager.poll(), Ok(PollOutcome::NewDuties(0, duties)));
        // Get the same duties again...
        assert_eq!(manager.poll(), Ok(PollOutcome::NoChange(0)));

        // Return new duties.
        let duties = EpochDuties {
            validator_index: 0,
            block_production_slot: Some(11),
        };
        beacon_node.set_next_shuffling_result(Ok(Some(duties)));
        assert_eq!(manager.poll(), Ok(PollOutcome::DutiesChanged(0, duties)));

        // Return no duties.
        beacon_node.set_next_shuffling_result(Ok(None));
        assert_eq!(manager.poll(), Ok(PollOutcome::UnknownValidatorOrEpoch(0)));
    }
}
