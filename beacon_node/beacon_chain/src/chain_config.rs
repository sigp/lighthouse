use serde_derive::{Deserialize, Serialize};
use types::Checkpoint;

pub const DEFAULT_FORK_CHOICE_BEFORE_PROPOSAL_TIMEOUT: u64 = 250;

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
    /// Number of milliseconds to wait for fork choice before proposing a block.
    ///
    /// If set to 0 then block proposal will not wait for fork choice at all.
    pub fork_choice_before_proposal_timeout_ms: u64,
    /// Number of skip slots in a row before the BN refuses to use connected builders during payload construction.
    pub builder_fallback_skips: usize,
    /// Number of skip slots in the past `SLOTS_PER_EPOCH` before the BN refuses to use connected
    /// builders during payload construction.
    pub builder_fallback_skips_per_epoch: usize,
    /// Number of epochs since finalization before the BN refuses to use connected builders during
    /// payload construction.
    pub builder_fallback_epochs_since_finalization: usize,
    /// Whether any chain health checks should be considered when deciding whether to use the builder API.
    pub builder_fallback_disable_checks: bool,
    pub count_unrealized: bool,
    /// Whether to apply paranoid checks to blocks proposed by this beacon node.
    pub paranoid_block_proposal: bool,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            import_max_skip_slots: None,
            weak_subjectivity_checkpoint: None,
            reconstruct_historic_states: false,
            enable_lock_timeouts: true,
            max_network_size: 10 * 1_048_576, // 10M
            fork_choice_before_proposal_timeout_ms: DEFAULT_FORK_CHOICE_BEFORE_PROPOSAL_TIMEOUT,
            // Builder fallback configs that are set in `clap` will override these.
            builder_fallback_skips: 3,
            builder_fallback_skips_per_epoch: 8,
            builder_fallback_epochs_since_finalization: 3,
            builder_fallback_disable_checks: false,
            count_unrealized: true,
            paranoid_block_proposal: false,
        }
    }
}
