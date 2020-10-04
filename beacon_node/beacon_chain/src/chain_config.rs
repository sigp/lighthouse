use serde_derive::{Deserialize, Serialize};
use types::Checkpoint;

/// There is a 693 block skip in the current canonical Medalla chain, we use 700 to be safe.
pub const DEFAULT_IMPORT_BLOCK_MAX_SKIP_SLOTS: u64 = 700;

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
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            import_max_skip_slots: Some(DEFAULT_IMPORT_BLOCK_MAX_SKIP_SLOTS),
            weak_subjectivity_checkpoint: None,
        }
    }
}
