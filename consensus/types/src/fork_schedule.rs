use std::collections::HashMap;

use crate::{ChainSpec, Slot};
use ethereum_types::H256;
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ForkType {
    Altair,
    Genesis,
}

#[derive(Debug, Clone)]
pub struct ForkContext {
    fork_to_digest: HashMap<ForkType, [u8; 4]>,
    digest_to_fork: HashMap<[u8; 4], ForkType>,
}

impl ForkContext {
    pub fn new(genesis_validators_root: H256, spec: &ChainSpec) -> Self {
        let genesis_fork_version = spec.genesis_fork_digest(genesis_validators_root);
        let altair_fork_version = spec.genesis_fork_digest(genesis_validators_root);
        let fork_to_digest = vec![
            (ForkType::Genesis, genesis_fork_version),
            (ForkType::Altair, altair_fork_version),
        ]
        .into_iter()
        .collect();
        let digest_to_fork = vec![
            (genesis_fork_version, ForkType::Genesis),
            (altair_fork_version, ForkType::Altair),
        ]
        .into_iter()
        .collect();
        Self {
            fork_to_digest,
            digest_to_fork,
        }
    }

    /// Returns the fork type given the context bytes/fork_digest.
    /// Returns None if context bytes doesn't correspond to any Fork.
    pub fn from_context_bytes(&self, context: [u8; 4]) -> Option<&ForkType> {
        self.digest_to_fork.get(&context)
    }

    /// Returns the context bytes/fork_digest corresponding to a fork type
    pub fn to_context_bytes(&self, fork_type: ForkType) -> [u8; 4] {
        self.fork_to_digest
            .get(&fork_type)
            .expect("All possible forks are initialized")
            .clone()
    }
}
