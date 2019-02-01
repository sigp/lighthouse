use super::{BeaconChain, ClientDB, SlotClock};
use types::{beacon_state::CommitteesError, PublicKey};

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Returns the the validator index (if any) for the given public key.
    ///
    /// Information is retrieved from the present `beacon_state.validator_registry`.
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

    /// Returns the number of slots the validator has been required to propose.
    ///
    /// Returns `None` if the `validator_index` is invalid.
    ///
    /// Information is retrieved from the present `beacon_state.validator_registry`.
    pub fn proposer_slots(&self, validator_index: usize) -> Option<u64> {
        if let Some(validator) = self.state.read().validator_registry.get(validator_index) {
            Some(validator.proposer_slots)
        } else {
            None
        }
    }

    /// Reads the slot clock, returns `None` if the slot is unavailable.
    ///
    /// The slot might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative slot).
    ///
    /// This is distinct to `present_slot`, which simply reads the latest state. If a
    /// call to `read_slot_clock` results in a higher slot than a call to `present_slot`,
    /// `self.state` should undergo per slot processing.
    pub fn read_slot_clock(&self) -> Option<u64> {
        match self.slot_clock.present_slot() {
            Ok(some_slot) => some_slot,
            _ => None,
        }
    }

    /// Returns slot of the present state.
    ///
    /// This is distinct to `read_slot_clock`, which reads from the actual system clock. If
    /// `self.state` has not been transitioned it is possible for the system clock to be on a
    /// different slot to what is returned from this call.
    pub fn present_slot(&self) -> u64 {
        self.state.read().slot
    }

    /// Returns the block proposer for a given slot.
    ///
    /// Information is read from the present `beacon_state` shuffling, so only information from the
    /// present and prior epoch is available.
    pub fn block_proposer(&self, slot: u64) -> Result<usize, CommitteesError> {
        let index = self
            .state
            .read()
            .get_beacon_proposer_index(slot, &self.spec)?;

        Ok(index)
    }

    /// Returns the justified slot for the present state.
    pub fn justified_slot(&self) -> u64 {
        self.state.read().justified_slot
    }

    /// Returns the attestation slot and shard for a given validator index.
    ///
    /// Information is read from the current state, so only information from the present and prior
    /// epoch is available.
    pub fn validator_attestion_slot_and_shard(
        &self,
        validator_index: usize,
    ) -> Result<Option<(u64, u64)>, CommitteesError> {
        if let Some((slot, shard, _committee)) = self
            .state
            .read()
            .attestation_slot_and_shard_for_validator(validator_index, &self.spec)?
        {
            Ok(Some((slot, shard)))
        } else {
            Ok(None)
        }
    }
}
