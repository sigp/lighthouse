use super::SlotClock;
use std::time::{Duration, SystemTime};

pub use std::time::SystemTimeError;

#[derive(Debug, PartialEq)]
pub enum Error {
    SlotDurationIsZero,
    SystemTimeError(String),
}

/// Determines the present slot based upon the present system time.
pub struct SystemTimeSlotClock {
    genesis_seconds: u64,
    slot_duration_seconds: u64,
}

impl SystemTimeSlotClock {
    /// Create a new `SystemTimeSlotClock`.
    ///
    /// Returns an Error if `slot_duration_seconds == 0`.
    pub fn new(
        genesis_seconds: u64,
        slot_duration_seconds: u64,
    ) -> Result<SystemTimeSlotClock, Error> {
        if slot_duration_seconds == 0 {
            Err(Error::SlotDurationIsZero)
        } else {
            Ok(Self {
                genesis_seconds,
                slot_duration_seconds,
            })
        }
    }
}

impl SlotClock for SystemTimeSlotClock {
    type Error = Error;

    fn present_slot(&self) -> Result<Option<u64>, Error> {
        let syslot_time = SystemTime::now();
        let duration_since_epoch = syslot_time.duration_since(SystemTime::UNIX_EPOCH)?;
        let duration_since_genesis =
            duration_since_epoch.checked_sub(Duration::from_secs(self.genesis_seconds));
        match duration_since_genesis {
            None => Ok(None),
            Some(d) => Ok(slot_from_duration(self.slot_duration_seconds, d)),
        }
    }
}

impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Error {
        Error::SystemTimeError(format!("{:?}", e))
    }
}

fn slot_from_duration(slot_duration_seconds: u64, duration: Duration) -> Option<u64> {
    duration.as_secs().checked_div(slot_duration_seconds)
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

        let now = SystemTime::now();
        let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let genesis = since_epoch.as_secs() - slot_time * 89;

        let clock = SystemTimeSlotClock {
            genesis_seconds: genesis,
            slot_duration_seconds: slot_time,
        };
        assert_eq!(clock.present_slot().unwrap(), Some(89));

        let clock = SystemTimeSlotClock {
            genesis_seconds: since_epoch.as_secs(),
            slot_duration_seconds: slot_time,
        };
        assert_eq!(clock.present_slot().unwrap(), Some(0));

        let clock = SystemTimeSlotClock {
            genesis_seconds: since_epoch.as_secs() - slot_time * 42 - 5,
            slot_duration_seconds: slot_time,
        };
        assert_eq!(clock.present_slot().unwrap(), Some(42));
    }

    #[test]
    fn test_slot_from_duration() {
        let slot_time = 100;

        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(0)),
            Some(0)
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(10)),
            Some(0)
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(100)),
            Some(1)
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(101)),
            Some(1)
        );
        assert_eq!(
            slot_from_duration(slot_time, Duration::from_secs(1000)),
            Some(10)
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
