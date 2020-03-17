use super::SlotClock;
use parking_lot::RwLock;
use std::convert::TryInto;
use std::time::Duration;
use types::Slot;

/// Determines the present slot based upon a manually-incremented UNIX timestamp.
pub struct ManualSlotClock {
    genesis_slot: Slot,
    /// Duration from UNIX epoch to genesis.
    genesis_duration: Duration,
    /// Duration from UNIX epoch to right now.
    current_time: RwLock<Duration>,
    /// The length of each slot.
    slot_duration: Duration,
}

impl Clone for ManualSlotClock {
    fn clone(&self) -> Self {
        ManualSlotClock {
            genesis_slot: self.genesis_slot.clone(),
            genesis_duration: self.genesis_duration.clone(),
            current_time: RwLock::new(self.current_time.read().clone()),
            slot_duration: self.slot_duration.clone(),
        }
    }
}

impl ManualSlotClock {
    pub fn set_slot(&self, slot: u64) {
        let slots_since_genesis = slot
            .checked_sub(self.genesis_slot.as_u64())
            .expect("slot must be post-genesis")
            .try_into()
            .expect("slot must fit within a u32");
        *self.current_time.write() =
            self.genesis_duration + self.slot_duration * slots_since_genesis;
    }

    pub fn advance_slot(&self) {
        self.set_slot(self.now().unwrap().as_u64() + 1)
    }

    pub fn duration_to_next_slot_from(&self, now: Duration) -> Option<Duration> {
        let genesis = self.genesis_duration;

        let slot_start = |slot: Slot| -> Duration {
            let slot = slot.as_u64() as u32;
            genesis + slot * self.slot_duration
        };

        if now >= genesis {
            Some(
                slot_start(self.slot_of(now)? + 1)
                    .checked_sub(now)
                    .expect("The next slot cannot start before now"),
            )
        } else {
            Some(
                genesis
                    .checked_sub(now)
                    .expect("Control flow ensures genesis is greater than or equal to now"),
            )
        }
    }

    pub fn duration_to_next_epoch_from(
        &self,
        now: Duration,
        slots_per_epoch: u64,
    ) -> Option<Duration> {
        let genesis = self.genesis_duration;

        let slot_start = |slot: Slot| -> Duration {
            let slot = slot.as_u64() as u32;
            genesis + slot * self.slot_duration
        };

        let epoch_start_slot = self
            .now()
            .map(|slot| slot.epoch(slots_per_epoch))
            .map(|epoch| (epoch + 1).start_slot(slots_per_epoch))?;

        if now >= genesis {
            Some(
                slot_start(epoch_start_slot)
                    .checked_sub(now)
                    .expect("The next epoch cannot start before now"),
            )
        } else {
            Some(
                genesis
                    .checked_sub(now)
                    .expect("Control flow ensures genesis is greater than or equal to now"),
            )
        }
    }
}

impl SlotClock for ManualSlotClock {
    fn new(genesis_slot: Slot, genesis_duration: Duration, slot_duration: Duration) -> Self {
        if slot_duration.as_millis() == 0 {
            panic!("ManualSlotClock cannot have a < 1ms slot duration");
        }

        Self {
            genesis_slot,
            current_time: RwLock::new(genesis_duration.clone()),
            genesis_duration,
            slot_duration,
        }
    }

    fn now(&self) -> Option<Slot> {
        self.slot_of(*self.current_time.read())
    }

    fn now_duration(&self) -> Option<Duration> {
        Some(*self.current_time.read())
    }

    fn slot_of(&self, now: Duration) -> Option<Slot> {
        let genesis = self.genesis_duration;

        if now >= genesis {
            let since_genesis = now
                .checked_sub(genesis)
                .expect("Control flow ensures now is greater than or equal to genesis");
            let slot =
                Slot::from((since_genesis.as_millis() / self.slot_duration.as_millis()) as u64);
            Some(slot + self.genesis_slot)
        } else {
            None
        }
    }

    fn duration_to_next_slot(&self) -> Option<Duration> {
        self.duration_to_next_slot_from(*self.current_time.read())
    }

    fn duration_to_next_epoch(&self, slots_per_epoch: u64) -> Option<Duration> {
        self.duration_to_next_epoch_from(*self.current_time.read(), slots_per_epoch)
    }

    fn slot_duration(&self) -> Duration {
        self.slot_duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_now() {
        let clock = ManualSlotClock::new(
            Slot::new(10),
            Duration::from_secs(0),
            Duration::from_secs(1),
        );
        assert_eq!(clock.now(), Some(Slot::new(10)));
        clock.set_slot(123);
        assert_eq!(clock.now(), Some(Slot::new(123)));
    }
}
