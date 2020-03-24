///! Maintains a hard-coded list of known forks and their slots at which they were activated.
use types::{Epoch, EthSpec, Slot, FAR_FUTURE_EPOCH};

mod forks;

/// A state-less function that provides the fork version given a set of active forks and a slot
/// number.
///
/// The disabled_forks parameter select which forks are disabled by their name.
pub fn current_fork_version(slot: Slot, disabled_forks: Vec<String>) -> [u8; 4] {
    let mut version = [0, 0, 0, 0];
    for (fork_name, fork_slot_no, fork_version) in forks::KNOWN_FORKS.iter() {
        if *fork_slot_no <= slot.as_u64() {
            if disabled_forks
                .iter()
                .find(|fork| **fork == String::from(*fork_name))
                .is_none()
            {
                version = fork_version.clone();
            }
        } else {
            break;
        }
    }
    version
}

pub fn next_fork_version(slot: Slot, disabled_forks: Vec<String>) -> [u8; 4] {
    let mut version = None;
    for (fork_name, fork_slot_no, fork_version) in forks::KNOWN_FORKS.iter() {
        if *fork_slot_no > slot.as_u64() {
            if disabled_forks
                .iter()
                .find(|fork| **fork == String::from(*fork_name))
                .is_none()
            {
                version = Some(fork_version.clone());
                break;
            }
        }
    }

    if let Some(result_version) = version {
        result_version
    } else {
        // if there is no next fork, use the current fork version
        current_fork_version(slot, disabled_forks)
    }
}

pub fn next_fork_epoch<T: EthSpec>(slot: Slot, disabled_forks: Vec<String>) -> Epoch {
    let mut next_fork_slot = None;
    for (fork_name, fork_slot_no, _fork_version) in forks::KNOWN_FORKS.iter() {
        if *fork_slot_no > slot.as_u64() {
            if disabled_forks
                .iter()
                .find(|fork| **fork == String::from(*fork_name))
                .is_none()
            {
                next_fork_slot = Some(Slot::new(*fork_slot_no));
                break;
            }
        }
    }

    if let Some(fork_slot) = next_fork_slot {
        fork_slot.epoch(T::slots_per_epoch())
    } else {
        FAR_FUTURE_EPOCH
    }
}
