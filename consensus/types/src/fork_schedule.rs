use crate::{ChainSpec, Slot};
use lazy_static::lazy_static;
use parking_lot::RwLock;

lazy_static! {
    static ref FORK_SCHEDULE: RwLock<Option<ForkSchedule>> = RwLock::new(None);
}

/// Initialise the global fork schedule.
///
/// MUST be called before any of the types that rely on it are used.
pub fn init_fork_schedule(fork_schedule: ForkSchedule) {
    *FORK_SCHEDULE.write() = Some(fork_schedule);
}

/// Read a copy of the fork schedule from the global variable.
pub fn get_fork_schedule() -> Option<ForkSchedule> {
    FORK_SCHEDULE.read().clone()
}

/// Convenience method for getting the fork schedule during an SSZ decode.
pub fn get_fork_schedule_ssz() -> Result<ForkSchedule, ssz::DecodeError> {
    get_fork_schedule()
        .ok_or_else(|| ssz::DecodeError::BytesInvalid("fork schedule not initialised".into()))
}

/// Constants related to hard-fork upgrades.
#[derive(Debug, Clone)]
pub struct ForkSchedule {
    /// A `None` value indicates that Altair will not take place in this schedule.
    pub altair_fork_slot: Option<Slot>,
}

impl From<&ChainSpec> for ForkSchedule {
    fn from(spec: &ChainSpec) -> Self {
        ForkSchedule {
            altair_fork_slot: Some(spec.altair_fork_slot),
        }
    }
}
