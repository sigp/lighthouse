use super::{BeaconChain, ClientDB, SlotClock};
use types::PublicKey;

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

    pub fn block_proposer(&self, slot: u64) -> Option<usize> {
        let present_slot = self.present_slot()?;
        let state = self.state(present_slot).ok()?;
        state.get_beacon_proposer_index(slot, &self.spec)
    }

    pub fn justified_slot(&self) -> u64 {
        self.justified_head
            .read()
            .expect("Justified head poisoned")
            .beacon_block
            .slot
    }
}
