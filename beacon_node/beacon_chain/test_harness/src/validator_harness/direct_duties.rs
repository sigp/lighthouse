use attester::{
    DutiesReader as AttesterDutiesReader, DutiesReaderError as AttesterDutiesReaderError,
};
use beacon_chain::BeaconChain;
use block_proposer::{
    DutiesReader as ProposerDutiesReader, DutiesReaderError as ProposerDutiesReaderError,
};
use db::ClientDB;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{PublicKey, Slot};

/// Connects directly to a borrowed `BeaconChain` and reads attester/proposer duties directly from
/// it.
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

impl<T: ClientDB, U: SlotClock> ProposerDutiesReader for DirectDuties<T, U> {
    fn is_block_production_slot(&self, slot: Slot) -> Result<bool, ProposerDutiesReaderError> {
        let validator_index = self
            .beacon_chain
            .validator_index(&self.pubkey)
            .ok_or_else(|| ProposerDutiesReaderError::UnknownValidator)?;

        match self.beacon_chain.block_proposer(slot) {
            Ok(proposer) if proposer == validator_index => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Err(ProposerDutiesReaderError::UnknownEpoch),
        }
    }
}

impl<T: ClientDB, U: SlotClock> AttesterDutiesReader for DirectDuties<T, U> {
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
                Err(_) => panic!("Error when getting validator attestation shard."),
            }
        } else {
            Err(AttesterDutiesReaderError::UnknownValidator)
        }
    }
}
