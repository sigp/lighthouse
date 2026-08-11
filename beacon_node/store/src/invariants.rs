//! Database invariant checks for the hot and cold databases.
//!
//! These checks verify the consistency of data stored in the database. They are designed to be
//! called from the HTTP API and from tests to detect data corruption or bugs in the store logic.
//!
//! See the `check_invariants` and `check_database_invariants` methods for the full list.

use crate::hdiff::StorageStrategy;
use crate::hot_cold_store::{ColdStateSummary, HotStateSummary};
use crate::{DBColumn, Error, ItemStore};
use crate::{HotColdDB, Split};
use serde::Serialize;
use ssz::Decode;
use std::cmp;
use std::collections::HashSet;
use types::*;

/// Result of running invariant checks on the database.
#[derive(Debug, Clone, Serialize)]
pub struct InvariantCheckResult {
    /// List of invariant violations found.
    pub violations: Vec<InvariantViolation>,
}

impl InvariantCheckResult {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn add_violation(&mut self, violation: InvariantViolation) {
        self.violations.push(violation);
    }

    pub fn merge(&mut self, other: InvariantCheckResult) {
        self.violations.extend(other.violations);
    }
}

impl Default for InvariantCheckResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Context data from the beacon chain needed for invariant checks.
///
/// This allows all invariant checks to live in the store crate while still checking
/// invariants that depend on fork choice, state cache, and custody context.
pub struct InvariantContext {
    /// Block roots tracked by fork choice (invariant 1).
    pub fork_choice_blocks: Vec<(Hash256, Slot)>,
    /// State roots held in the in-memory state cache (invariant 8).
    pub state_cache_roots: Vec<Hash256>,
    /// Custody columns for the current epoch (invariant 7).
    pub custody_columns: Vec<ColumnIndex>,
    /// Compressed pubkey bytes from the in-memory validator pubkey cache, indexed by validator index
    /// (invariant 9).
    pub pubkey_cache_pubkeys: Vec<Vec<u8>>,
}

/// A single invariant violation.
#[derive(Debug, Clone, Serialize)]
pub enum InvariantViolation {
    /// Invariant 1: fork choice block consistency.
    ///
    /// ```text
    /// block in fork_choice && descends_from_finalized -> block in hot_db
    /// ```
    ForkChoiceBlockMissing { block_root: Hash256, slot: Slot },
    /// Invariant 2: block and state consistency.
    ///
    /// ```text
    /// block in hot_db && block.slot >= split.slot
    ///   -> state_summary for block.state_root() in hot_db
    /// ```
    HotBlockMissingStateSummary {
        block_root: Hash256,
        slot: Slot,
        state_root: Hash256,
    },
    /// Invariant 3: state summary diff consistency.
    ///
    /// ```text
    /// state_summary in hot_db
    ///   -> state diff/snapshot/nothing in hot_db according to hierarchy rules
    /// ```
    HotStateMissingSnapshot { state_root: Hash256, slot: Slot },
    /// Invariant 3: state summary diff consistency (missing diff).
    ///
    /// ```text
    /// state_summary in hot_db
    ///   -> state diff/snapshot/nothing in hot_db according to hierarchy rules
    /// ```
    HotStateMissingDiff { state_root: Hash256, slot: Slot },
    /// Invariant 3: DiffFrom/ReplayFrom base slot must reference an existing summary.
    ///
    /// ```text
    /// state_summary in hot_db
    ///   -> state diff/snapshot/nothing in hot_db according to hierarchy rules
    /// ```
    HotStateBaseSummaryMissing {
        slot: Slot,
        base_state_root: Hash256,
    },
    /// Invariant 4: state summary chain consistency.
    ///
    /// ```text
    /// state_summary in hot_db && state_summary.slot > split.slot
    ///   -> state_summary for previous_state_root in hot_db
    /// ```
    HotStateMissingPreviousSummary {
        slot: Slot,
        previous_state_root: Hash256,
    },
    /// Invariant 5: block and execution payload consistency.
    ///
    /// ```text
    /// block in hot_db && !prune_payloads -> payload for block.root in hot_db
    /// ```
    ExecutionPayloadMissing { block_root: Hash256, slot: Slot },
    /// Invariant 6: block and blobs consistency.
    ///
    /// ```text
    /// block in hot_db && num_blob_commitments > 0
    ///   -> blob_list for block.root in hot_db
    /// ```
    BlobSidecarMissing { block_root: Hash256, slot: Slot },
    /// Invariant 7: block and data columns consistency.
    ///
    /// ```text
    /// block in hot_db && num_blob_commitments > 0
    ///   && block.slot >= earliest_available_slot
    ///   && data_column_idx in custody_columns
    ///   -> (block_root, data_column_idx) in hot_db
    /// ```
    DataColumnMissing {
        block_root: Hash256,
        slot: Slot,
        column_index: ColumnIndex,
    },
    /// Invariant 8: state cache and disk consistency.
    ///
    /// ```text
    /// state in state_cache -> state_summary in hot_db
    /// ```
    StateCacheMissingSummary { state_root: Hash256 },
    /// Invariant 9: pubkey cache consistency.
    ///
    /// ```text
    /// state_summary in hot_db
    ///   -> all validator pubkeys from state.validators are in the hot_db
    /// ```
    PubkeyCacheMissing { validator_index: usize },
    /// Invariant 9b: pubkey cache value mismatch.
    ///
    /// ```text
    /// pubkey_cache[i] == hot_db(PubkeyCache)[i]
    /// ```
    PubkeyCacheMismatch { validator_index: usize },
    /// Invariant 10: block root indices mapping.
    ///
    /// ```text
    /// oldest_block_slot <= i < split.slot
    ///   -> block_root for slot i in cold_db
    ///   && block for block_root in hot_db
    /// ```
    ColdBlockRootMissing {
        slot: Slot,
        oldest_block_slot: Slot,
        split_slot: Slot,
    },
    /// Invariant 10: block root index references a block that must exist.
    ///
    /// ```text
    /// oldest_block_slot <= i < split.slot
    ///   -> block_root for slot i in cold_db
    ///   && block for block_root in hot_db
    /// ```
    ColdBlockRootOrphan { slot: Slot, block_root: Hash256 },
    /// Invariant 11: state root indices mapping.
    ///
    /// ```text
    /// (i <= state_lower_limit || i >= min(split.slot, state_upper_limit)) && i < split.slot
    ///   -> i |-> state_root in cold_db(BeaconStateRoots)
    ///   && state_root |-> cold_state_summary in cold_db(BeaconColdStateSummary)
    ///   && cold_state_summary.slot == i
    /// ```
    ColdStateRootMissing {
        slot: Slot,
        state_lower_limit: Slot,
        state_upper_limit: Slot,
        split_slot: Slot,
    },
    /// Invariant 11: state root index must have a cold state summary.
    ///
    /// ```text
    /// (i <= state_lower_limit || i >= min(split.slot, state_upper_limit)) && i < split.slot
    ///   -> i |-> state_root in cold_db(BeaconStateRoots)
    ///   && state_root |-> cold_state_summary in cold_db(BeaconColdStateSummary)
    ///   && cold_state_summary.slot == i
    /// ```
    ColdStateRootMissingSummary { slot: Slot, state_root: Hash256 },
    /// Invariant 11: cold state summary slot must match index slot.
    ///
    /// ```text
    /// (i <= state_lower_limit || i >= min(split.slot, state_upper_limit)) && i < split.slot
    ///   -> i |-> state_root in cold_db(BeaconStateRoots)
    ///   && state_root |-> cold_state_summary in cold_db(BeaconColdStateSummary)
    ///   && cold_state_summary.slot == i
    /// ```
    ColdStateRootSlotMismatch {
        slot: Slot,
        state_root: Hash256,
        summary_slot: Slot,
    },
    /// Invariant 12: cold state diff consistency.
    ///
    /// ```text
    /// cold_state_summary in cold_db
    ///   -> slot |-> state diff/snapshot/nothing in cold_db according to diff hierarchy
    /// ```
    ColdStateMissingSnapshot { state_root: Hash256, slot: Slot },
    /// Invariant 12: cold state diff consistency (missing diff).
    ///
    /// ```text
    /// cold_state_summary in cold_db
    ///   -> slot |-> state diff/snapshot/nothing in cold_db according to diff hierarchy
    /// ```
    ColdStateMissingDiff { state_root: Hash256, slot: Slot },
    /// Invariant 12: DiffFrom/ReplayFrom base slot must reference an existing summary.
    ///
    /// ```text
    /// cold_state_summary in cold_db
    ///   -> slot |-> state diff/snapshot/nothing in cold_db according to diff hierarchy
    /// ```
    ColdStateBaseSummaryMissing { slot: Slot, base_slot: Slot },
}

impl<E: EthSpec, Hot: ItemStore, Cold: ItemStore> HotColdDB<E, Hot, Cold> {
    /// Run all database invariant checks.
    ///
    /// The `ctx` parameter provides data from the beacon chain layer (fork choice, state cache,
    /// custody columns, pubkey cache) so that all invariant checks can live in this single file.
    pub fn check_invariants(&self, ctx: &InvariantContext) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();
        let split = self.get_split_info();

        result.merge(self.check_fork_choice_block_consistency(ctx)?);
        result.merge(self.check_hot_block_invariants(&split, ctx)?);
        result.merge(self.check_hot_state_summary_diff_consistency()?);
        result.merge(self.check_hot_state_summary_chain_consistency(&split)?);
        result.merge(self.check_state_cache_consistency(ctx)?);
        result.merge(self.check_cold_block_root_indices(&split)?);
        result.merge(self.check_cold_state_root_indices(&split)?);
        result.merge(self.check_cold_state_diff_consistency()?);
        result.merge(self.check_pubkey_cache_consistency(ctx)?);

        Ok(result)
    }

    /// Invariant 1 (Hot DB): Fork choice block consistency.
    ///
    /// ```text
    /// block in fork_choice && descends_from_finalized -> block in hot_db
    /// ```
    ///
    /// Every canonical fork choice block (descending from finalized) must exist in the hot
    /// database. Pruned non-canonical fork blocks may linger in the proto-array and are
    /// excluded from this check.
    fn check_fork_choice_block_consistency(
        &self,
        ctx: &InvariantContext,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        for &(block_root, slot) in &ctx.fork_choice_blocks {
            let exists = self
                .hot_db
                .key_exists(DBColumn::BeaconBlock, block_root.as_slice())?;
            if !exists {
                result
                    .add_violation(InvariantViolation::ForkChoiceBlockMissing { block_root, slot });
            }
        }

        Ok(result)
    }

    /// Invariants 2, 5, 6, 7 (Hot DB): Block-related consistency checks.
    ///
    /// Iterates hot DB blocks once and checks:
    /// - Invariant 2: block-state summary consistency
    /// - Invariant 5: execution payload consistency (when prune_payloads=false)
    /// - Invariant 6: blob sidecar consistency (Deneb to Fulu)
    /// - Invariant 7: data column consistency (post-Fulu, when custody_columns provided)
    fn check_hot_block_invariants(
        &self,
        split: &Split,
        ctx: &InvariantContext,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let check_payloads = !self.get_config().prune_payloads;
        let bellatrix_fork_slot = self
            .spec
            .bellatrix_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));
        let deneb_fork_slot = self
            .spec
            .deneb_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));
        let fulu_fork_slot = self
            .spec
            .fulu_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));
        let gloas_fork_slot = self
            .spec
            .gloas_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));
        let oldest_blob_slot = self.get_blob_info().oldest_blob_slot;
        let oldest_data_column_slot = self.get_data_column_info().oldest_data_column_slot;

        for res in self.hot_db.iter_column::<Hash256>(DBColumn::BeaconBlock) {
            let (block_root, block_bytes) = res?;
            let block = SignedBlindedBeaconBlock::<E>::from_ssz_bytes(&block_bytes, &self.spec)?;
            let slot = block.slot();

            // Invariant 2: block-state consistency.
            if slot >= split.slot {
                let state_root = block.state_root();
                let has_summary = self
                    .hot_db
                    .key_exists(DBColumn::BeaconStateHotSummary, state_root.as_slice())?;
                if !has_summary {
                    result.add_violation(InvariantViolation::HotBlockMissingStateSummary {
                        block_root,
                        slot,
                        state_root,
                    });
                }
            }

            // Invariant 5: execution payload consistency.
            if check_payloads
                && let Some(bellatrix_slot) = bellatrix_fork_slot
                && slot >= bellatrix_slot
            {
                if let Some(gloas_slot) = gloas_fork_slot
                    && slot >= gloas_slot
                {
                    // For Gloas there is never a true payload stored at slot 0.
                    // TODO(gloas): still need to account for non-canonical payloads once pruning
                    // is implemented.
                    if slot != 0 && !self.payload_envelope_exists(&block_root)? {
                        result.add_violation(InvariantViolation::ExecutionPayloadMissing {
                            block_root,
                            slot,
                        });
                    }
                } else if !self.execution_payload_exists(&block_root)? {
                    result.add_violation(InvariantViolation::ExecutionPayloadMissing {
                        block_root,
                        slot,
                    });
                }
            }

            // Invariant 6: blob sidecar consistency.
            // Only check blocks that actually have blob KZG commitments — blocks with 0
            // commitments legitimately have no blob sidecars stored.
            if let Some(deneb_slot) = deneb_fork_slot
                && let Some(oldest_blob) = oldest_blob_slot
                && slot >= deneb_slot
                && slot >= oldest_blob
                && fulu_fork_slot.is_none_or(|fulu_slot| slot < fulu_slot)
                && block.num_expected_blobs() > 0
            {
                let has_blob = self
                    .blobs_db
                    .key_exists(DBColumn::BeaconBlob, block_root.as_slice())?;
                if !has_blob {
                    result
                        .add_violation(InvariantViolation::BlobSidecarMissing { block_root, slot });
                }
            }

            // Invariant 7: data column consistency.
            // Only check blocks that actually have blob KZG commitments.
            // TODO(gloas): reconsider this invariant — non-canonical payloads won't have
            // their data column sidecars stored.
            if !ctx.custody_columns.is_empty()
                && let Some(fulu_slot) = fulu_fork_slot
                && let Some(oldest_dc) = oldest_data_column_slot
                && slot >= fulu_slot
                && slot >= oldest_dc
                && block.num_expected_blobs() > 0
            {
                let stored_columns = self.get_data_column_keys(block_root)?;
                for col_idx in &ctx.custody_columns {
                    if !stored_columns.contains(col_idx) {
                        result.add_violation(InvariantViolation::DataColumnMissing {
                            block_root,
                            slot,
                            column_index: *col_idx,
                        });
                    }
                }
            }
        }

        Ok(result)
    }

    /// Invariant 3 (Hot DB): State summary diff/snapshot consistency.
    ///
    /// ```text
    /// state_summary in hot_db
    ///   -> state diff/snapshot/nothing in hot_db per HDiff hierarchy rules
    /// ```
    ///
    /// Each hot state summary should have the correct storage artifact (snapshot, diff, or
    /// nothing) according to the HDiff hierarchy configuration. The hierarchy uses the
    /// anchor_slot as its start point for the hot DB.
    fn check_hot_state_summary_diff_consistency(&self) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let anchor_slot = self.get_anchor_info().anchor_slot;

        // Collect all summary slots and their strategies in a first pass.
        let mut known_state_roots = HashSet::new();
        let mut base_state_refs: Vec<(Slot, Hash256)> = Vec::new();

        for res in self
            .hot_db
            .iter_column::<Hash256>(DBColumn::BeaconStateHotSummary)
        {
            let (state_root, value) = res?;
            let summary = HotStateSummary::from_ssz_bytes(&value)?;

            known_state_roots.insert(state_root);

            match self.hierarchy.storage_strategy(summary.slot, anchor_slot)? {
                StorageStrategy::Snapshot => {
                    let has_snapshot = self
                        .hot_db
                        .key_exists(DBColumn::BeaconStateHotSnapshot, state_root.as_slice())?;
                    if !has_snapshot {
                        result.add_violation(InvariantViolation::HotStateMissingSnapshot {
                            state_root,
                            slot: summary.slot,
                        });
                    }
                }
                StorageStrategy::DiffFrom(base_slot) => {
                    let has_diff = self
                        .hot_db
                        .key_exists(DBColumn::BeaconStateHotDiff, state_root.as_slice())?;
                    if !has_diff {
                        result.add_violation(InvariantViolation::HotStateMissingDiff {
                            state_root,
                            slot: summary.slot,
                        });
                    }
                    if let Ok(base_root) = summary.diff_base_state.get_root(base_slot) {
                        base_state_refs.push((summary.slot, base_root));
                    }
                }
                StorageStrategy::ReplayFrom(base_slot) => {
                    if let Ok(base_root) = summary.diff_base_state.get_root(base_slot) {
                        base_state_refs.push((summary.slot, base_root));
                    }
                }
            }
        }

        // Verify that all diff base state roots reference existing summaries.
        for (slot, base_state_root) in base_state_refs {
            if !known_state_roots.contains(&base_state_root) {
                result.add_violation(InvariantViolation::HotStateBaseSummaryMissing {
                    slot,
                    base_state_root,
                });
            }
        }

        Ok(result)
    }

    /// Invariant 4 (Hot DB): State summary chain consistency.
    ///
    /// ```text
    /// state_summary in hot_db && state_summary.slot > split.slot
    ///   -> state_summary for previous_state_root in hot_db
    /// ```
    ///
    /// The chain of `previous_state_root` links must be continuous back to the split state.
    /// The split state itself is the boundary and does not need a predecessor in the hot DB.
    fn check_hot_state_summary_chain_consistency(
        &self,
        split: &Split,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        for res in self
            .hot_db
            .iter_column::<Hash256>(DBColumn::BeaconStateHotSummary)
        {
            let (_state_root, value) = res?;
            let summary = HotStateSummary::from_ssz_bytes(&value)?;

            if summary.slot > split.slot {
                let prev_root = summary.previous_state_root;
                let has_prev = self
                    .hot_db
                    .key_exists(DBColumn::BeaconStateHotSummary, prev_root.as_slice())?;
                if !has_prev {
                    result.add_violation(InvariantViolation::HotStateMissingPreviousSummary {
                        slot: summary.slot,
                        previous_state_root: prev_root,
                    });
                }
            }
        }

        Ok(result)
    }

    /// Invariant 8 (Hot DB): State cache and disk consistency.
    ///
    /// ```text
    /// state in state_cache -> state_summary in hot_db
    /// ```
    ///
    /// Every state held in the in-memory state cache (including the finalized state) should
    /// have a corresponding hot state summary on disk.
    fn check_state_cache_consistency(
        &self,
        ctx: &InvariantContext,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        for &state_root in &ctx.state_cache_roots {
            let has_summary = self
                .hot_db
                .key_exists(DBColumn::BeaconStateHotSummary, state_root.as_slice())?;
            if !has_summary {
                result.add_violation(InvariantViolation::StateCacheMissingSummary { state_root });
            }
        }

        Ok(result)
    }

    /// Invariant 10 (Cold DB): Block root indices.
    ///
    /// ```text
    /// oldest_block_slot <= i < split.slot
    ///   -> block_root for slot i in cold_db
    ///   && block for block_root in hot_db
    /// ```
    ///
    /// Every slot in the cold range (from `oldest_block_slot` to `split.slot`) should have a
    /// block root index entry, and the referenced block should exist in the hot DB. Note that
    /// skip slots store the most recent non-skipped block's root, so `block.slot()` may differ
    /// from the index slot.
    fn check_cold_block_root_indices(&self, split: &Split) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let anchor_info = self.get_anchor_info();

        if anchor_info.oldest_block_slot >= split.slot {
            return Ok(result);
        }

        for slot_val in anchor_info.oldest_block_slot.as_u64()..split.slot.as_u64() {
            let slot = Slot::new(slot_val);

            let slot_bytes = slot_val.to_be_bytes();
            let block_root_bytes = self
                .cold_db
                .get_bytes(DBColumn::BeaconBlockRoots, &slot_bytes)?;

            let Some(root_bytes) = block_root_bytes else {
                result.add_violation(InvariantViolation::ColdBlockRootMissing {
                    slot,
                    oldest_block_slot: anchor_info.oldest_block_slot,
                    split_slot: split.slot,
                });
                continue;
            };

            if root_bytes.len() != 32 {
                return Err(Error::InvalidKey(format!(
                    "cold block root at slot {slot} has invalid length {}",
                    root_bytes.len()
                )));
            }

            let block_root = Hash256::from_slice(&root_bytes);
            let block_exists = self
                .hot_db
                .key_exists(DBColumn::BeaconBlock, block_root.as_slice())?;
            if !block_exists {
                result.add_violation(InvariantViolation::ColdBlockRootOrphan { slot, block_root });
            }
        }

        Ok(result)
    }

    /// Invariant 11 (Cold DB): State root indices.
    ///
    /// ```text
    /// (i <= state_lower_limit || i >= min(split.slot, state_upper_limit)) && i < split.slot
    ///   -> i |-> state_root in cold_db(BeaconStateRoots)
    ///   && state_root |-> cold_state_summary in cold_db(BeaconColdStateSummary)
    ///   && cold_state_summary.slot == i
    /// ```
    fn check_cold_state_root_indices(&self, split: &Split) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let anchor_info = self.get_anchor_info();

        // Expected slots are: (i <= state_lower_limit || i >= effective_upper) && i < split.slot
        // where effective_upper = min(split.slot, state_upper_limit).
        for slot_val in 0..split.slot.as_u64() {
            let slot = Slot::new(slot_val);

            if slot <= anchor_info.state_lower_limit
                || slot >= cmp::min(split.slot, anchor_info.state_upper_limit)
            {
                let slot_bytes = slot_val.to_be_bytes();
                let Some(root_bytes) = self
                    .cold_db
                    .get_bytes(DBColumn::BeaconStateRoots, &slot_bytes)?
                else {
                    result.add_violation(InvariantViolation::ColdStateRootMissing {
                        slot,
                        state_lower_limit: anchor_info.state_lower_limit,
                        state_upper_limit: anchor_info.state_upper_limit,
                        split_slot: split.slot,
                    });
                    continue;
                };

                if root_bytes.len() != 32 {
                    return Err(Error::InvalidKey(format!(
                        "cold state root at slot {slot} has invalid length {}",
                        root_bytes.len()
                    )));
                }

                let state_root = Hash256::from_slice(&root_bytes);

                match self
                    .cold_db
                    .get_bytes(DBColumn::BeaconColdStateSummary, state_root.as_slice())?
                {
                    None => {
                        result.add_violation(InvariantViolation::ColdStateRootMissingSummary {
                            slot,
                            state_root,
                        });
                    }
                    Some(summary_bytes) => {
                        let summary = ColdStateSummary::from_ssz_bytes(&summary_bytes)?;
                        if summary.slot != slot {
                            result.add_violation(InvariantViolation::ColdStateRootSlotMismatch {
                                slot,
                                state_root,
                                summary_slot: summary.slot,
                            });
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Invariant 12 (Cold DB): Cold state diff/snapshot consistency.
    ///
    /// ```text
    /// cold_state_summary in cold_db
    ///   -> state diff/snapshot/nothing in cold_db per HDiff hierarchy rules
    /// ```
    ///
    /// Each cold state summary should have the correct storage artifact according to the
    /// HDiff hierarchy. Cold states always use genesis (slot 0) as the hierarchy start since
    /// they are finalized and have no anchor_slot dependency.
    fn check_cold_state_diff_consistency(&self) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let mut summary_slots = HashSet::new();
        let mut base_slot_refs = Vec::new();

        for res in self
            .cold_db
            .iter_column::<Hash256>(DBColumn::BeaconColdStateSummary)
        {
            let (state_root, value) = res?;
            let summary = ColdStateSummary::from_ssz_bytes(&value)?;

            summary_slots.insert(summary.slot);

            let slot_bytes = summary.slot.as_u64().to_be_bytes();

            match self
                .hierarchy
                .storage_strategy(summary.slot, Slot::new(0))?
            {
                StorageStrategy::Snapshot => {
                    let has_snapshot = self
                        .cold_db
                        .key_exists(DBColumn::BeaconStateSnapshot, &slot_bytes)?;
                    if !has_snapshot {
                        result.add_violation(InvariantViolation::ColdStateMissingSnapshot {
                            state_root,
                            slot: summary.slot,
                        });
                    }
                }
                StorageStrategy::DiffFrom(base_slot) => {
                    let has_diff = self
                        .cold_db
                        .key_exists(DBColumn::BeaconStateDiff, &slot_bytes)?;
                    if !has_diff {
                        result.add_violation(InvariantViolation::ColdStateMissingDiff {
                            state_root,
                            slot: summary.slot,
                        });
                    }
                    base_slot_refs.push((summary.slot, base_slot));
                }
                StorageStrategy::ReplayFrom(base_slot) => {
                    base_slot_refs.push((summary.slot, base_slot));
                }
            }
        }

        // Verify that all DiffFrom/ReplayFrom base slots reference existing summaries.
        for (slot, base_slot) in base_slot_refs {
            if !summary_slots.contains(&base_slot) {
                result.add_violation(InvariantViolation::ColdStateBaseSummaryMissing {
                    slot,
                    base_slot,
                });
            }
        }

        Ok(result)
    }

    /// Invariant 9 (Hot DB): Pubkey cache consistency.
    ///
    /// ```text
    /// all validator pubkeys from states are in hot_db(PubkeyCache)
    /// ```
    ///
    /// Checks that the in-memory pubkey cache and the on-disk PubkeyCache column have the same
    /// number of entries AND that each pubkey matches at every validator index.
    fn check_pubkey_cache_consistency(
        &self,
        ctx: &InvariantContext,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        // Read on-disk pubkeys by sequential validator index (matching how they are stored
        // with Hash256::from_low_u64_be(index) as key).
        // Iterate in-memory pubkeys and verify each matches on disk.
        for (validator_index, in_memory_bytes) in ctx.pubkey_cache_pubkeys.iter().enumerate() {
            let mut key = [0u8; 32];
            key[24..].copy_from_slice(&(validator_index as u64).to_be_bytes());
            match self.hot_db.get_bytes(DBColumn::PubkeyCache, &key)? {
                Some(on_disk_bytes) if in_memory_bytes != &on_disk_bytes => {
                    result
                        .add_violation(InvariantViolation::PubkeyCacheMismatch { validator_index });
                }
                None => {
                    result
                        .add_violation(InvariantViolation::PubkeyCacheMissing { validator_index });
                }
                _ => {}
            }
        }

        Ok(result)
    }
}
