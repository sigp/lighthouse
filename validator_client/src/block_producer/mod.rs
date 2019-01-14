mod traits;

use self::traits::{BeaconNode, BeaconNodeError};
use crate::EpochDuties;
use slot_clock::SlotClock;
use spec::ChainSpec;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use types::BeaconBlock;

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
    BeaconNodeError(BeaconNodeError),
}

pub struct BlockProducer<T: SlotClock, U: BeaconNode> {
    pub last_processed_slot: u64,
    _spec: Arc<ChainSpec>,
    epoch_map: Arc<RwLock<HashMap<u64, EpochDuties>>>,
    slot_clock: Arc<RwLock<T>>,
    beacon_node: U,
}

impl<T: SlotClock, U: BeaconNode> BlockProducer<T, U> {
    pub fn new(
        spec: Arc<ChainSpec>,
        epoch_map: Arc<RwLock<HashMap<u64, EpochDuties>>>,
        slot_clock: Arc<RwLock<T>>,
        beacon_node: U,
    ) -> Self {
        Self {
            last_processed_slot: 0,
            _spec: spec,
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

        // If this is a new slot.
        if slot > self.last_processed_slot {
            let is_block_production_slot = {
                let epoch_map = self
                    .epoch_map
                    .read()
                    .map_err(|_| PollError::EpochMapPoisoned)?;
                match epoch_map.get(&slot) {
                    None => return Ok(PollOutcome::ProducerDutiesUnknown),
                    Some(duties) => duties.is_block_production_slot(slot)
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
