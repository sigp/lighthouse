use crate::Slot;
use lazy_static::lazy_static;
use parking_lot::RwLock;

lazy_static! {
    pub static ref FORK_SCHEDULE: RwLock<Option<ForkSchedule>> = RwLock::new(None);
}

/// Initialise the global fork schedule.
///
/// MUST be called before any of the types that rely on it are used.
pub fn init_fork_schedule(fork_schedule: ForkSchedule) {
    *FORK_SCHEDULE.write() = Some(fork_schedule);
}

/// Constants related to hard-fork upgrades.
#[derive(Debug)]
pub struct ForkSchedule {
    pub altair_fork_slot: Slot,
    pub altair_fork_version: [u8; 4],
}
