pub use proto_array::{DisallowedReOrgOffsets, ReOrgThreshold};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use types::{Checkpoint, Epoch, ProgressiveBalancesMode};

pub const DEFAULT_RE_ORG_THRESHOLD: ReOrgThreshold = ReOrgThreshold(20);
pub const DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION: Epoch = Epoch::new(2);
/// Default to 1/12th of the slot, which is 1 second on mainnet.
pub const DEFAULT_RE_ORG_CUTOFF_DENOMINATOR: u32 = 12;
pub const DEFAULT_FORK_CHOICE_BEFORE_PROPOSAL_TIMEOUT: u64 = 250;

/// Default fraction of a slot lookahead for payload preparation (12/3 = 4 seconds on mainnet).
pub const DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR: u32 = 3;

/// Fraction of a slot lookahead for fork choice in the state advance timer (500ms on mainnet).
pub const FORK_CHOICE_LOOKAHEAD_FACTOR: u32 = 24;

/// Cache only a small number of states in the parallel cache by default.
pub const DEFAULT_PARALLEL_STATE_CACHE_SIZE: usize = 2;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    /// Maximum number of slots to skip when importing an attestation.
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
    /// Maximum percentage of committee weight at which to attempt re-orging the canonical head.
    pub re_org_threshold: Option<ReOrgThreshold>,
    /// Maximum number of epochs since finalization for attempting a proposer re-org.
    pub re_org_max_epochs_since_finalization: Epoch,
    /// Maximum delay after the start of the slot at which to propose a reorging block.
    pub re_org_cutoff_millis: Option<u64>,
    /// Additional epoch offsets at which re-orging block proposals are not permitted.
    ///
    /// By default this list is empty, but it can be useful for reacting to network conditions, e.g.
    /// slow gossip of re-org blocks at slot 1 in the epoch.
    pub re_org_disallowed_offsets: DisallowedReOrgOffsets,
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
    /// When set to `true`, forget any valid/invalid/optimistic statuses in fork choice during start
    /// up.
    pub always_reset_payload_statuses: bool,
    /// Whether to apply paranoid checks to blocks proposed by this beacon node.
    pub paranoid_block_proposal: bool,
    /// Optionally set timeout for calls to checkpoint sync endpoint.
    pub checkpoint_sync_url_timeout: u64,
    /// The offset before the start of a proposal slot at which payload attributes should be sent.
    ///
    /// Low values are useful for execution engines which don't improve their payload after the
    /// first call, and high values are useful for ensuring the EL is given ample notice.
    pub prepare_payload_lookahead: Duration,
    /// Use EL-free optimistic sync for the finalized part of the chain.
    pub optimistic_finalized_sync: bool,
    /// The size of the shuffling cache,
    pub shuffling_cache_size: usize,
    /// If using a weak-subjectivity sync, whether we should download blocks all the way back to
    /// genesis.
    pub genesis_backfill: bool,
    /// Whether to send payload attributes every slot, regardless of connected proposers.
    ///
    /// This is useful for block builders and testing.
    pub always_prepare_payload: bool,
    /// Whether to use `ProgressiveBalancesCache` in unrealized FFG progression calculation.
    pub progressive_balances_mode: ProgressiveBalancesMode,
    /// Number of epochs between each migration of data from the hot database to the freezer.
    pub epochs_per_migration: u64,
    /// Size of the promise cache for de-duplicating parallel state requests.
    pub parallel_state_cache_size: usize,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            import_max_skip_slots: None,
            weak_subjectivity_checkpoint: None,
            reconstruct_historic_states: false,
            enable_lock_timeouts: true,
            max_network_size: 10 * 1_048_576, // 10M
            re_org_threshold: Some(DEFAULT_RE_ORG_THRESHOLD),
            re_org_max_epochs_since_finalization: DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION,
            re_org_cutoff_millis: None,
            re_org_disallowed_offsets: DisallowedReOrgOffsets::default(),
            fork_choice_before_proposal_timeout_ms: DEFAULT_FORK_CHOICE_BEFORE_PROPOSAL_TIMEOUT,
            // Builder fallback configs that are set in `clap` will override these.
            builder_fallback_skips: 3,
            builder_fallback_skips_per_epoch: 8,
            builder_fallback_epochs_since_finalization: 3,
            builder_fallback_disable_checks: false,
            always_reset_payload_statuses: false,
            paranoid_block_proposal: false,
            checkpoint_sync_url_timeout: 60,
            prepare_payload_lookahead: Duration::from_secs(4),
            // This value isn't actually read except in tests.
            optimistic_finalized_sync: true,
            shuffling_cache_size: crate::shuffling_cache::DEFAULT_CACHE_SIZE,
            genesis_backfill: false,
            always_prepare_payload: false,
            progressive_balances_mode: ProgressiveBalancesMode::Checked,
            epochs_per_migration: crate::migrate::DEFAULT_EPOCHS_PER_MIGRATION,
            parallel_state_cache_size: DEFAULT_PARALLEL_STATE_CACHE_SIZE,
        }
    }
}

impl ChainConfig {
    /// The latest delay from the start of the slot at which to attempt a 1-slot re-org.
    pub fn re_org_cutoff(&self, seconds_per_slot: u64) -> Duration {
        self.re_org_cutoff_millis
            .map(Duration::from_millis)
            .unwrap_or_else(|| {
                Duration::from_secs(seconds_per_slot) / DEFAULT_RE_ORG_CUTOFF_DENOMINATOR
            })
    }
}
