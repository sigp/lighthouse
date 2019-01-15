mod grpc;
mod test_node;
mod traits;

use self::traits::{BeaconNode, BeaconNodeError};
use crate::EpochDuties;
use slot_clock::SlotClock;
use spec::ChainSpec;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use types::BeaconBlock;

type EpochMap = HashMap<u64, EpochDuties>;

#[derive(Debug, PartialEq)]
pub enum PollOutcome {
    BlockProduced,
    SlashableBlockNotProduced,
    BlockProductionNotRequired,
    ProducerDutiesUnknown,
    SlotAlreadyProcessed,
    BeaconNodeUnableToProduceBlock,
}

#[derive(Debug, PartialEq)]
pub enum PollError {
    SlotClockError,
    SlotUnknowable,
    EpochMapPoisoned,
    SlotClockPoisoned,
    EpochLengthIsZero,
    BeaconNodeError(BeaconNodeError),
}

pub struct BlockProducer<T: SlotClock, U: BeaconNode> {
    pub last_processed_slot: u64,
    spec: Arc<ChainSpec>,
    epoch_map: Arc<RwLock<HashMap<u64, EpochDuties>>>,
    slot_clock: Arc<RwLock<T>>,
    beacon_node: Arc<U>,
}

impl<T: SlotClock, U: BeaconNode> BlockProducer<T, U> {
    pub fn new(
        spec: Arc<ChainSpec>,
        epoch_map: Arc<RwLock<EpochMap>>,
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

impl<T: SlotClock, U: BeaconNode> BlockProducer<T, U> {
    /// "Poll" to see if the validator is required to take any action.
    ///
    /// The slot clock will be read and any new actions undertaken.
    pub fn poll(&mut self) -> Result<PollOutcome, PollError> {
        let slot = self
            .slot_clock
            .read()
            .map_err(|_| PollError::SlotClockPoisoned)?
            .present_slot()
            .map_err(|_| PollError::SlotClockError)?
            .ok_or(PollError::SlotUnknowable)?;

        let epoch = slot.checked_div(self.spec.epoch_length)
            .ok_or(PollError::EpochLengthIsZero)?;

        // If this is a new slot.
        if slot > self.last_processed_slot {
            let is_block_production_slot = {
                let epoch_map = self
                    .epoch_map
                    .read()
                    .map_err(|_| PollError::EpochMapPoisoned)?;
                match epoch_map.get(&epoch) {
                    None => return Ok(PollOutcome::ProducerDutiesUnknown),
                    Some(duties) => duties.is_block_production_slot(slot),
                }
            };

            if is_block_production_slot {
                self.last_processed_slot = slot;

                self.produce_block(slot)
            } else {
                Ok(PollOutcome::BlockProductionNotRequired)
            }
        } else {
            Ok(PollOutcome::SlotAlreadyProcessed)
        }
    }

    fn produce_block(&mut self, slot: u64) -> Result<PollOutcome, PollError> {
        if let Some(block) = self.beacon_node.produce_beacon_block(slot)? {
            if self.safe_to_produce(&block) {
                let block = self.sign_block(block);
                self.beacon_node.publish_beacon_block(block)?;
                Ok(PollOutcome::BlockProduced)
            } else {
                Ok(PollOutcome::SlashableBlockNotProduced)
            }
        } else {
            Ok(PollOutcome::BeaconNodeUnableToProduceBlock)
        }
    }

    fn sign_block(&mut self, block: BeaconBlock) -> BeaconBlock {
        // TODO: sign the block
        self.store_produce(&block);
        block
    }

    fn safe_to_produce(&self, _block: &BeaconBlock) -> bool {
        // TODO: ensure the producer doesn't produce slashable blocks.
        true
    }

    fn store_produce(&mut self, _block: &BeaconBlock) {
        // TODO: record this block production to prevent future slashings.
    }
}

impl From<BeaconNodeError> for PollError {
    fn from(e: BeaconNodeError) -> PollError {
        PollError::BeaconNodeError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::test_node::TestBeaconNode;
    use super::*;
    use slot_clock::TestingSlotClock;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    // TODO: implement more thorough testing.
    //
    // These tests should serve as a good example for future tests.

    #[test]
    pub fn polling() {
        let mut rng = XorShiftRng::from_seed([42; 16]);

        let spec = Arc::new(ChainSpec::foundation());
        let epoch_map = Arc::new(RwLock::new(EpochMap::new()));
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
        epoch_map.write().unwrap().insert(produce_epoch, duties);

        // One slot before production slot...
        slot_clock.write().unwrap().set_slot(produce_slot - 1);
        assert_eq!(block_producer.poll(), Ok(PollOutcome::BlockProductionNotRequired));

        // On the produce slot...
        slot_clock.write().unwrap().set_slot(produce_slot);
        assert_eq!(block_producer.poll(), Ok(PollOutcome::BlockProduced));

        // Trying the same produce slot again...
        slot_clock.write().unwrap().set_slot(produce_slot);
        assert_eq!(block_producer.poll(), Ok(PollOutcome::SlotAlreadyProcessed));

        // One slot after the produce slot...
        slot_clock.write().unwrap().set_slot(produce_slot + 1);
        assert_eq!(block_producer.poll(), Ok(PollOutcome::BlockProductionNotRequired));

        // In an epoch without known duties...
        slot_clock.write().unwrap().set_slot((produce_epoch + 1) * spec.epoch_length);
        assert_eq!(block_producer.poll(), Ok(PollOutcome::ProducerDutiesUnknown));
    }
}
