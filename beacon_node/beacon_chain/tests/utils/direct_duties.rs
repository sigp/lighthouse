use beacon_chain::{block_production::Error as BlockProductionError, BeaconChain};
use block_producer::{DutiesReader, DutiesReaderError};
use db::ClientDB;
use slot_clock::SlotClock;
use types::PublicKey;

pub struct DirectDuties<'a, T: ClientDB, U: SlotClock> {
    beacon_chain: &'a BeaconChain<T, U>,
    pubkey: PublicKey,
}

impl<'a, T: ClientDB, U: SlotClock> DirectDuties<'a, T, U> {
    pub fn new(pubkey: PublicKey, beacon_chain: &'a BeaconChain<T, U>) -> Self {
        Self {
            beacon_chain,
            pubkey,
        }
    }
}

impl<'a, T: ClientDB, U: SlotClock> DutiesReader for DirectDuties<'a, T, U>
where
    BlockProductionError: From<<U>::Error>,
{
    fn is_block_production_slot(&self, _epoch: u64, slot: u64) -> Result<bool, DutiesReaderError> {
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
