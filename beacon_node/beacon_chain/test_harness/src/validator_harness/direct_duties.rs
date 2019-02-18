use attester::{
    DutiesReader as AttesterDutiesReader, DutiesReaderError as AttesterDutiesReaderError,
};
use beacon_chain::BeaconChain;
use block_producer::{
    DutiesReader as ProducerDutiesReader, DutiesReaderError as ProducerDutiesReaderError,
};
use db::ClientDB;
use fork_choice::ForkChoice;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{PublicKey, Slot};

/// Connects directly to a borrowed `BeaconChain` and reads attester/proposer duties directly from
/// it.
pub struct DirectDuties<T: ClientDB, U: SlotClock, F: ForkChoice> {
    beacon_chain: Arc<BeaconChain<T, U, F>>,
    pubkey: PublicKey,
}

impl<T: ClientDB, U: SlotClock, F: ForkChoice> DirectDuties<T, U, F> {
    pub fn new(pubkey: PublicKey, beacon_chain: Arc<BeaconChain<T, U, F>>) -> Self {
        Self {
            beacon_chain,
            pubkey,
        }
    }
}

impl<T: ClientDB, U: SlotClock, F: ForkChoice> ProducerDutiesReader for DirectDuties<T, U, F> {
    fn is_block_production_slot(&self, slot: Slot) -> Result<bool, ProducerDutiesReaderError> {
        let validator_index = self
            .beacon_chain
            .validator_index(&self.pubkey)
            .ok_or_else(|| ProducerDutiesReaderError::UnknownValidator)?;

        match self.beacon_chain.block_proposer(slot) {
            Ok(proposer) if proposer == validator_index => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Err(ProducerDutiesReaderError::UnknownEpoch),
        }
    }
}

impl<T: ClientDB, U: SlotClock, F: ForkChoice> AttesterDutiesReader for DirectDuties<T, U, F> {
    fn validator_index(&self) -> Option<u64> {
        match self.beacon_chain.validator_index(&self.pubkey) {
            Some(index) => Some(index as u64),
            None => None,
        }
    }

    fn attestation_shard(&self, slot: Slot) -> Result<Option<u64>, AttesterDutiesReaderError> {
        if let Some(validator_index) = self.validator_index() {
            match self
                .beacon_chain
                .validator_attestion_slot_and_shard(validator_index as usize)
            {
                Ok(Some((attest_slot, attest_shard))) if attest_slot == slot => {
                    Ok(Some(attest_shard))
                }
                Ok(Some(_)) => Ok(None),
                Ok(None) => Err(AttesterDutiesReaderError::UnknownEpoch),
                Err(_) => unreachable!("Error when getting validator attestation shard."),
            }
        } else {
            Err(AttesterDutiesReaderError::UnknownValidator)
        }
    }
}
