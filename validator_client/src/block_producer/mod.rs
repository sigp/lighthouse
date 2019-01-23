mod grpc;
mod service;
#[cfg(test)]
mod test_node;
pub mod traits;

use self::traits::{BeaconNode, BeaconNodeError, DutiesReader, DutiesReaderError};
use slot_clock::SlotClock;
use spec::ChainSpec;
use std::sync::{Arc, RwLock};
use types::BeaconBlock;

pub use self::service::BlockProducerService;

#[derive(Debug, PartialEq)]
pub enum PollOutcome {
    /// A new block was produced.
    BlockProduced(u64),
    /// A block was not produced as it would have been slashable.
    SlashableBlockNotProduced(u64),
    /// The validator duties did not require a block to be produced.
    BlockProductionNotRequired(u64),
    /// The duties for the present epoch were not found.
    ProducerDutiesUnknown(u64),
    /// The slot has already been processed, execution was skipped.
    SlotAlreadyProcessed(u64),
    /// The Beacon Node was unable to produce a block at that slot.
    BeaconNodeUnableToProduceBlock(u64),
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

/// A polling state machine which performs block production duties, based upon some epoch duties
/// (`EpochDutiesMap`) and a concept of time (`SlotClock`).
///
/// Ensures that messages are not slashable.
///
/// Relies upon an external service to keep the `EpochDutiesMap` updated.
pub struct BlockProducer<T: SlotClock, U: BeaconNode, V: DutiesReader> {
    pub last_processed_slot: u64,
    spec: Arc<ChainSpec>,
    epoch_map: Arc<V>,
    slot_clock: Arc<RwLock<T>>,
    beacon_node: Arc<U>,
}

impl<T: SlotClock, U: BeaconNode, V: DutiesReader> BlockProducer<T, U, V> {
    /// Returns a new instance where `last_processed_slot == 0`.
    pub fn new(
        spec: Arc<ChainSpec>,
        epoch_map: Arc<V>,
        slot_clock: Arc<RwLock<T>>,
        beacon_node: Arc<U>,
    ) -> Self {
        Self {
            last_processed_slot: 0,
            spec,
            epoch_map,
            slot_clock,
            beacon_node,
        }
    }
}

impl<T: SlotClock, U: BeaconNode, V: DutiesReader> BlockProducer<T, U, V> {
    /// "Poll" to see if the validator is required to take any action.
    ///
    /// The slot clock will be read and any new actions undertaken.
    pub fn poll(&mut self) -> Result<PollOutcome, Error> {
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

        // If this is a new slot.
        if slot > self.last_processed_slot {
            let is_block_production_slot =
                match self.epoch_map.is_block_production_slot(epoch, slot) {
                    Ok(result) => result,
                    Err(DutiesReaderError::UnknownEpoch) => {
                        return Ok(PollOutcome::ProducerDutiesUnknown(slot))
                    }
                    Err(DutiesReaderError::Poisoned) => return Err(Error::EpochMapPoisoned),
                };

            if is_block_production_slot {
                self.last_processed_slot = slot;

                self.produce_block(slot)
            } else {
                Ok(PollOutcome::BlockProductionNotRequired(slot))
            }
        } else {
            Ok(PollOutcome::SlotAlreadyProcessed(slot))
        }
    }

    /// Produce a block at some slot.
    ///
    /// Assumes that a block is required at this slot (does not check the duties).
    ///
    /// Ensures the message is not slashable.
    ///
    /// !!! UNSAFE !!!
    ///
    /// The slash-protection code is not yet implemented. There is zero protection against
    /// slashing.
    fn produce_block(&mut self, slot: u64) -> Result<PollOutcome, Error> {
        if let Some(block) = self.beacon_node.produce_beacon_block(slot)? {
            if self.safe_to_produce(&block) {
                let block = self.sign_block(block);
                self.beacon_node.publish_beacon_block(block)?;
                Ok(PollOutcome::BlockProduced(slot))
            } else {
                Ok(PollOutcome::SlashableBlockNotProduced(slot))
            }
        } else {
            Ok(PollOutcome::BeaconNodeUnableToProduceBlock(slot))
        }
    }

    /// Consumes a block, returning that block signed by the validators private key.
    ///
    /// Important: this function will not check to ensure the block is not slashable. This must be
    /// done upstream.
    fn sign_block(&mut self, block: BeaconBlock) -> BeaconBlock {
        // TODO: sign the block
        // https://github.com/sigp/lighthouse/issues/160
        self.store_produce(&block);
        block
    }

    /// Returns `true` if signing a block is safe (non-slashable).
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn safe_to_produce(&self, _block: &BeaconBlock) -> bool {
        // TODO: ensure the producer doesn't produce slashable blocks.
        // https://github.com/sigp/lighthouse/issues/160
        true
    }

    /// Record that a block was produced so that slashable votes may not be made in the future.
    ///
    /// !!! UNSAFE !!!
    ///
    /// Important: this function is presently stubbed-out. It provides ZERO SAFETY.
    fn store_produce(&mut self, _block: &BeaconBlock) {
        // TODO: record this block production to prevent future slashings.
        // https://github.com/sigp/lighthouse/issues/160
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
    use crate::duties::EpochDuties;
    use crate::duties::EpochDutiesMap;
    use slot_clock::TestingSlotClock;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    // TODO: implement more thorough testing.
    // https://github.com/sigp/lighthouse/issues/160
    //
    // These tests should serve as a good example for future tests.

    #[test]
    pub fn polling() {
        let mut rng = XorShiftRng::from_seed([42; 16]);

        let spec = Arc::new(ChainSpec::foundation());
        let epoch_map = Arc::new(EpochDutiesMap::new());
        let slot_clock = Arc::new(RwLock::new(TestingSlotClock::new(0)));
        let beacon_node = Arc::new(TestBeaconNode::default());

        let mut block_producer = BlockProducer::new(
            spec.clone(),
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
        );

        // Configure responses from the BeaconNode.
        beacon_node.set_next_produce_result(Ok(Some(BeaconBlock::random_for_test(&mut rng))));
        beacon_node.set_next_publish_result(Ok(true));

        // Setup some valid duties for the validator
        let produce_slot = 100;
        let duties = EpochDuties {
            block_production_slot: Some(produce_slot),
            ..std::default::Default::default()
        };
        let produce_epoch = produce_slot / spec.epoch_length;
        epoch_map.insert(produce_epoch, duties);

        // One slot before production slot...
        slot_clock.write().unwrap().set_slot(produce_slot - 1);
        assert_eq!(
            block_producer.poll(),
            Ok(PollOutcome::BlockProductionNotRequired(produce_slot - 1))
        );

        // On the produce slot...
        slot_clock.write().unwrap().set_slot(produce_slot);
        assert_eq!(
            block_producer.poll(),
            Ok(PollOutcome::BlockProduced(produce_slot))
        );

        // Trying the same produce slot again...
        slot_clock.write().unwrap().set_slot(produce_slot);
        assert_eq!(
            block_producer.poll(),
            Ok(PollOutcome::SlotAlreadyProcessed(produce_slot))
        );

        // One slot after the produce slot...
        slot_clock.write().unwrap().set_slot(produce_slot + 1);
        assert_eq!(
            block_producer.poll(),
            Ok(PollOutcome::BlockProductionNotRequired(produce_slot + 1))
        );

        // In an epoch without known duties...
        let slot = (produce_epoch + 1) * spec.epoch_length;
        slot_clock.write().unwrap().set_slot(slot);
        assert_eq!(
            block_producer.poll(),
            Ok(PollOutcome::ProducerDutiesUnknown(slot))
        );
    }
}
