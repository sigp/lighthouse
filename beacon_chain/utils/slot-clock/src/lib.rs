use std::time::{Duration, SystemTime, SystemTimeError};

pub fn slot_now(
    genesis_seconds: u64,
    slot_duration_seconds: u64,
) -> Result<Option<u64>, SystemTimeError> {
    let sys_time = SystemTime::now();
    let duration_since_epoch = sys_time.duration_since(SystemTime::UNIX_EPOCH)?;
    let duration_since_genesis =
        duration_since_epoch.checked_sub(Duration::from_secs(genesis_seconds));
    match duration_since_genesis {
        None => Ok(None),
        Some(d) => Ok(slot_from_duration(slot_duration_seconds, d)),
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
        let s_time = 100;

        let now = SystemTime::now();
        let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let genesis = since_epoch.as_secs() - s_time * 89;
        assert_eq!(slot_now(genesis, s_time).unwrap(), Some(89));

        let genesis = since_epoch.as_secs();
        assert_eq!(slot_now(genesis, s_time).unwrap(), Some(0));

        let genesis = since_epoch.as_secs() - s_time * 42 - 5;
        assert_eq!(slot_now(genesis, s_time).unwrap(), Some(42));
    }

    #[test]
    fn test_slot_from_duration() {
        let s_time = 100;

        assert_eq!(slot_from_duration(s_time, Duration::from_secs(0)), Some(0));
        assert_eq!(slot_from_duration(s_time, Duration::from_secs(10)), Some(0));
        assert_eq!(
            slot_from_duration(s_time, Duration::from_secs(100)),
            Some(1)
        );
        assert_eq!(
            slot_from_duration(s_time, Duration::from_secs(101)),
            Some(1)
        );
        assert_eq!(
            slot_from_duration(s_time, Duration::from_secs(1000)),
            Some(10)
        );
    }

    #[test]
    fn test_slot_from_duration_slot_time_zero() {
        let s_time = 0;

        assert_eq!(slot_from_duration(s_time, Duration::from_secs(0)), None);
        assert_eq!(slot_from_duration(s_time, Duration::from_secs(10)), None);
        assert_eq!(slot_from_duration(s_time, Duration::from_secs(1000)), None);
    }
}
