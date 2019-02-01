use super::{BeaconChain, ClientDB, SlotClock};
use types::{beacon_state::CommitteesError, PublicKey};

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotClockError,
    CommitteesError(CommitteesError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn validator_index(&self, pubkey: &PublicKey) -> Option<usize> {
        for (i, validator) in self
            .head()
            .beacon_state
            .validator_registry
            .iter()
            .enumerate()
        {
            if validator.pubkey == *pubkey {
                return Some(i);
            }
        }
        None
    }

    pub fn proposer_slots(&self, validator_index: usize) -> Option<u64> {
        if let Some(validator) = self.state.read().validator_registry.get(validator_index) {
            Some(validator.proposer_slots)
        } else {
            None
        }
    }

    pub fn present_slot(&self) -> Option<u64> {
        match self.slot_clock.present_slot() {
            Ok(some_slot) => some_slot,
            _ => None,
        }
    }

    pub fn block_proposer(&self, slot: u64) -> Result<usize, CommitteesError> {
        let index = self
            .state
            .read()
            .get_beacon_proposer_index(slot, &self.spec)?;

        Ok(index)
    }

    pub fn justified_slot(&self) -> u64 {
        self.state.read().justified_slot
    }

    pub fn validator_attestion_slot_and_shard(&self, validator_index: usize) -> Option<(u64, u64)> {
        let (slot, shard, _committee) = self
            .state
            .read()
            .attestation_slot_and_shard_for_validator(validator_index, &self.spec)
            .ok()?;
        Some((slot, shard))
    }
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}
