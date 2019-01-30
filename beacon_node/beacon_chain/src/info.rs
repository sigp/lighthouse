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
        let slot = self.present_slot()?;
        let state = self.state(slot).ok()?;

        if let Some(validator) = state.validator_registry.get(validator_index) {
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
        // TODO: fix unwrap
        let present_slot = self.present_slot().unwrap();
        // TODO: fix unwrap
        let state = self.state(present_slot).unwrap();
        let index = state.get_beacon_proposer_index(slot, &self.spec)?;

        Ok(index)
    }

    pub fn justified_slot(&self) -> u64 {
        self.justified_head
            .read()
            .expect("Justified head poisoned")
            .beacon_block
            .slot
    }

    pub fn validator_attestion_slot_and_shard(&self, validator_index: usize) -> Option<(u64, u64)> {
        let present_slot = self.present_slot()?;
        let state = self.state(present_slot).ok()?;

        state
            .attestation_slot_and_shard_for_validator(validator_index, &self.spec)
            .ok()
    }
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}
