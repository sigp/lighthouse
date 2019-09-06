#[macro_use]
extern crate lazy_static;

mod metrics;
mod system_time_slot_clock;
mod testing_slot_clock;

use std::time::{Duration, Instant, SystemTime, SystemTimeError, UNIX_EPOCH};

pub use crate::system_time_slot_clock::SystemTimeSlotClock;
pub use crate::testing_slot_clock::TestingSlotClock;
pub use metrics::scrape_for_metrics;
pub use types::Slot;

pub trait SlotClock: Send + Sync + Sized {
    fn from_eth2_genesis(
        genesis_slot: Slot,
        genesis_seconds: u64,
        slot_duration: Duration,
    ) -> Result<Self, SystemTimeError> {
        let duration_between_now_and_unix_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let duration_between_unix_epoch_and_genesis = Duration::from_secs(genesis_seconds);

        let genesis_instant = if duration_between_now_and_unix_epoch
            < duration_between_unix_epoch_and_genesis
        {
            Instant::now()
                + (duration_between_unix_epoch_and_genesis - duration_between_now_and_unix_epoch)
        } else {
            Instant::now()
                - (duration_between_now_and_unix_epoch - duration_between_unix_epoch_and_genesis)
        };

        Ok(Self::new(genesis_slot, genesis_instant, slot_duration))
    }

    fn new(genesis_slot: Slot, genesis: Instant, slot_duration: Duration) -> Self;

    fn now(&self) -> Option<Slot>;

    fn duration_to_next_slot(&self) -> Option<Duration>;

    fn slot_duration(&self) -> Duration;
}
