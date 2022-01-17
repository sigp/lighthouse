use serde_derive::{Deserialize, Serialize};
use types::Checkpoint;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    /// Maximum number of slots to skip when importing a consensus message (e.g., block,
    /// attestation, etc).
    ///
    /// If `None`, there is no limit.
    pub import_max_skip_slots: Option<u64>,
    /// A user-input `Checkpoint` that must exist in the beacon chain's sync path.
    ///
    /// If `None`, there is no weak subjectivity verification.
    pub weak_subjectivity_checkpoint: Option<Checkpoint>,
    /// Determine whether to reconstruct historic states, usually after a checkpoint sync.
    pub reconstruct_historic_states: bool,
    /// Whether timeouts on `TimeoutRwLock`s are enabled or not.
    pub enable_lock_timeouts: bool,
    /// The max size of a message that can be sent over the network.
    pub max_network_size: usize,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            import_max_skip_slots: None,
            weak_subjectivity_checkpoint: None,
            reconstruct_historic_states: false,
            enable_lock_timeouts: true,
            max_network_size: 10 * 1_048_576, // 10M
        }
    }
}
