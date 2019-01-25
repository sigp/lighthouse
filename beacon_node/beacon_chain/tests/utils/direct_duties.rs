use beacon_chain::{block_production::Error as BlockProductionError, BeaconChain};
use block_producer::{DutiesReader, DutiesReaderError};
use db::ClientDB;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::PublicKey;

pub struct DirectDuties<T: ClientDB, U: SlotClock> {
    beacon_chain: Arc<BeaconChain<T, U>>,
    pubkey: PublicKey,
}

impl<T: ClientDB, U: SlotClock> DirectDuties<T, U> {
    pub fn new(pubkey: PublicKey, beacon_chain: Arc<BeaconChain<T, U>>) -> Self {
        Self {
            beacon_chain,
            pubkey,
        }
    }
}

impl<T: ClientDB, U: SlotClock> DutiesReader for DirectDuties<T, U>
where
    BlockProductionError: From<<U>::Error>,
{
    fn is_block_production_slot(&self, slot: u64) -> Result<bool, DutiesReaderError> {
        let validator_index = self
            .beacon_chain
            .validator_index(&self.pubkey)
            .ok_or_else(|| DutiesReaderError::UnknownValidator)?;

        match self.beacon_chain.block_proposer(slot) {
            Some(proposer) if proposer == validator_index => Ok(true),
            Some(_) => Ok(false),
            None => Err(DutiesReaderError::UnknownEpoch),
        }
    }
}
