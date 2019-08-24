use super::SlotClock;
use std::time::{Duration, SystemTime};
use types::Slot;

pub use std::time::SystemTimeError;

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotDurationIsZero,
    SystemTimeError(String),
}

/// Determines the present slot based upon the present system time.
#[derive(Clone)]
pub struct SystemTimeSlotClock {
    genesis_slot: Slot,
    genesis_seconds: u64,
    slot_duration_seconds: u64,
}

impl SlotClock for SystemTimeSlotClock {
    type Error = Error;

    /// Create a new `SystemTimeSlotClock`.
    ///
    /// Returns an Error if `slot_duration_seconds == 0`.
    fn new(genesis_slot: Slot, genesis_seconds: u64, slot_duration_seconds: u64) -> Self {
        Self {
            genesis_slot,
            genesis_seconds,
            slot_duration_seconds,
        }
    }

    fn present_slot(&self) -> Result<Option<Slot>, Error> {
        if self.slot_duration_seconds == 0 {
            return Err(Error::SlotDurationIsZero);
        }

        let syslot_time = SystemTime::now();
        let duration_since_epoch = syslot_time.duration_since(SystemTime::UNIX_EPOCH)?;
        let duration_since_genesis =
            duration_since_epoch.checked_sub(Duration::from_secs(self.genesis_seconds));

        match duration_since_genesis {
            None => Ok(None),
            Some(d) => Ok(slot_from_duration(self.slot_duration_seconds, d)
                .and_then(|s| Some(s + self.genesis_slot))),
        }
    }

    fn duration_to_next_slot(&self) -> Result<Option<Duration>, Error> {
        duration_to_next_slot(self.genesis_seconds, self.slot_duration_seconds)
    }

    fn slot_duration_millis(&self) -> u64 {
        self.slot_duration_seconds * 1000
    }
}

impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Error {
        Error::SystemTimeError(format!("{:?}", e))
    }
}

fn slot_from_duration(slot_duration_seconds: u64, duration: Duration) -> Option<Slot> {
    Some(Slot::new(
        duration.as_secs().checked_div(slot_duration_seconds)?,
    ))
}
// calculate the duration to the next slot
fn duration_to_next_slot(
    genesis_time: u64,
    seconds_per_slot: u64,
) -> Result<Option<Duration>, Error> {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    let genesis_time = Duration::from_secs(genesis_time);

    if now < genesis_time {
        return Ok(None);
    }

    let since_genesis = now - genesis_time;

    let elapsed_slots = since_genesis.as_secs() / seconds_per_slot;

    let next_slot_start_seconds = (elapsed_slots + 1)
        .checked_mul(seconds_per_slot)
        .expect("Next slot time should not overflow u64");

    let time_to_next_slot = Duration::from_secs(next_slot_start_seconds) - since_genesis;

    Ok(Some(time_to_next_slot))
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
     * Note: these tests are using actual system times and could fail if they are executed on a
     * very slow machine.
     */
    #[test]
    fn test_slot_now() {
        let slot_time = 100;
        let genesis_slot = Slot::new(0);

        let now = SystemTime::now();
        let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let genesis = since_epoch.as_secs() - slot_time * 89;

        let clock = SystemTimeSlotClock {
            genesis_slot,
            genesis_seconds: genesis,
            slot_duration_seconds: slot_time,
        };
        assert_eq!(clock.present_slot().unwrap(), Some(Slot::new(89)));

        let clock = SystemTimeSlotClock {
            genesis_slot,
            genesis_seconds: since_epoch.as_secs(),
            slot_duration_seconds: slot_time,
        };
        assert_eq!(clock.present_slot().unwrap(), Some(Slot::new(0)));

        let clock = SystemTimeSlotClock {
            genesis_slot,
            genesis_seconds: since_epoch.as_secs() - slot_time * 42 - 5,
            slot_duration_seconds: slot_time,
        };
        assert_eq!(clock.present_slot().unwrap(), Some(Slot::new(42)));
    }

    #[test]
    fn test_slot_from_duration() {
        let slot_time = 100;

        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(0)),
            Some(Slot::new(0))
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(10)),
            Some(Slot::new(0))
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(100)),
            Some(Slot::new(1))
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(101)),
            Some(Slot::new(1))
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(1000)),
            Some(Slot::new(10))
        );
    }

    #[test]
    fn test_slot_from_duration_slot_time_zero() {
        let slot_time = 0;

        assert_eq!(slot_from_duration(slot_time, Duration::from_secs(0)), None);
        assert_eq!(slot_from_duration(slot_time, Duration::from_secs(10)), None);
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(1000)),
            None
        );
    }
}
