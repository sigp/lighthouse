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
    /// Total number of checks performed.
    pub checks_performed: usize,
}

impl InvariantCheckResult {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            checks_performed: 0,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn add_violation(&mut self, violation: InvariantViolation) {
        self.violations.push(violation);
    }

    pub fn inc_checks(&mut self) {
        self.checks_performed += 1;
    }

    pub fn merge(&mut self, other: InvariantCheckResult) {
        self.violations.extend(other.violations);
        self.checks_performed += other.checks_performed;
    }
}

impl Default for InvariantCheckResult {
    fn default() -> Self {
        Self::new()
    }
}

/// A single invariant violation.
#[derive(Debug, Clone, Serialize)]
pub enum InvariantViolation {
    /// Hot block has no corresponding hot state summary.
    HotBlockMissingStateSummary {
        block_root: Hash256,
        slot: Slot,
        state_root: Hash256,
    },
    /// Hot state summary should have a snapshot but none found.
    HotStateMissingSnapshot { state_root: Hash256, slot: Slot },
    /// Hot state summary should have a diff but none found.
    HotStateMissingDiff { state_root: Hash256, slot: Slot },
    /// Hot state summary's DiffFrom/ReplayFrom base slot has no summary.
    HotStateBaseSummaryMissing { slot: Slot, base_slot: Slot },
    /// Hot state summary's previous_state_root has no summary.
    HotStateMissingPreviousSummary {
        slot: Slot,
        previous_state_root: Hash256,
    },
    /// Block has no execution payload or envelope (prune_payloads=false).
    ExecutionPayloadMissing { block_root: Hash256, slot: Slot },
    /// Block has no blob sidecar entry.
    BlobSidecarMissing { block_root: Hash256, slot: Slot },
    /// State in cache has no hot state summary on disk.
    StateCacheMissingSummary { state_root: Hash256 },
    /// Cold block root index missing for a slot.
    ColdBlockRootMissing {
        slot: Slot,
        oldest_block_slot: Slot,
        split_slot: Slot,
    },
    /// Cold block root index references a block not in hot DB.
    ColdBlockRootOrphan { slot: Slot, block_root: Hash256 },
    /// Cold state root index missing for a slot.
    ColdStateRootMissing {
        slot: Slot,
        state_lower_limit: Slot,
        state_upper_limit: Slot,
        split_slot: Slot,
    },
    /// Cold state root index references a state with no cold summary.
    ColdStateRootMissingSummary { slot: Slot, state_root: Hash256 },
    /// Cold state summary slot doesn't match the state root index slot.
    ColdStateRootSlotMismatch {
        slot: Slot,
        state_root: Hash256,
        summary_slot: Slot,
    },
    /// Cold state summary should have a snapshot but none found.
    ColdStateMissingSnapshot { state_root: Hash256, slot: Slot },
    /// Cold state summary should have a diff but none found.
    ColdStateMissingDiff { state_root: Hash256, slot: Slot },
    /// Cold state summary's DiffFrom/ReplayFrom base slot has no summary.
    ColdStateBaseSummaryMissing { slot: Slot, base_slot: Slot },
    /// Fork choice references a block not in hot DB.
    ForkChoiceBlockMissing { block_root: Hash256, slot: Slot },
    /// Block missing a custody data column.
    DataColumnMissing {
        block_root: Hash256,
        slot: Slot,
        column_index: ColumnIndex,
    },
    /// Pubkey cache count mismatch between memory and disk.
    PubkeyCacheCountMismatch { in_memory: usize, on_disk: usize },
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> HotColdDB<E, Hot, Cold> {
    /// Run all store-level database invariant checks.
    ///
    /// Checks invariants 2-6, 8, 10-12.
    ///
    /// This function does NOT check invariants requiring beacon chain state:
    /// - Invariant 1 (fork choice block consistency) — requires fork choice
    /// - Invariant 7 (data column consistency) — requires custody context
    /// - Invariant 9 (pubkey cache) — requires validator pubkey cache
    ///
    /// Use `BeaconChain::check_database_invariants` for a complete check.
    pub fn check_invariants(
        &self,
        custody_columns: Option<&[ColumnIndex]>,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();
        let split = self.get_split_info();

        result.merge(self.check_hot_block_invariants(&split, custody_columns)?);
        result.merge(self.check_hot_state_summary_diff_consistency(&split)?);
        result.merge(self.check_hot_state_summary_chain_consistency(&split)?);
        result.merge(self.check_state_cache_consistency()?);
        result.merge(self.check_cold_block_root_indices(&split)?);
        result.merge(self.check_cold_state_root_indices(&split)?);
        result.merge(self.check_cold_state_diff_consistency(&split)?);

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
        custody_columns: Option<&[ColumnIndex]>,
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
        let oldest_blob_slot = self.get_blob_info().oldest_blob_slot;
        let oldest_data_column_slot = self.get_data_column_info().oldest_data_column_slot;

        for res in self.hot_db.iter_column::<Hash256>(DBColumn::BeaconBlock) {
            let (block_root, block_bytes) = res?;
            let block = SignedBeaconBlock::<E, BlindedPayload<E>>::from_ssz_bytes(
                &block_bytes,
                &self.spec,
            )?;
            let slot = block.slot();

            // Invariant 2: block-state consistency.
            result.inc_checks();
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
            if check_payloads {
                if let Some(bellatrix_slot) = bellatrix_fork_slot {
                    if slot >= bellatrix_slot {
                        result.inc_checks();
                        if !self.execution_payload_exists(&block_root)?
                            && !self.payload_envelope_exists(&block_root)?
                        {
                            result.add_violation(InvariantViolation::ExecutionPayloadMissing {
                                block_root,
                                slot,
                            });
                        }
                    }
                }
            }

            // Invariant 6: blob sidecar consistency.
            if let Some(deneb_slot) = deneb_fork_slot {
                if let Some(oldest_blob) = oldest_blob_slot {
                    let is_pre_fulu = fulu_fork_slot.is_none_or(|fulu_slot| slot < fulu_slot);
                    if slot >= deneb_slot && slot >= oldest_blob && is_pre_fulu {
                        result.inc_checks();
                        let has_blob = self
                            .blobs_db
                            .key_exists(DBColumn::BeaconBlob, block_root.as_slice())?;
                        if !has_blob {
                            result.add_violation(InvariantViolation::BlobSidecarMissing {
                                block_root,
                                slot,
                            });
                        }
                    }
                }
            }

            // Invariant 7: data column consistency.
            if let Some(custody_cols) = custody_columns {
                if let Some(fulu_slot) = fulu_fork_slot {
                    if let Some(oldest_dc) = oldest_data_column_slot {
                        if slot >= fulu_slot && slot >= oldest_dc {
                            result.inc_checks();
                            let stored_columns = self.get_data_column_keys(block_root)?;
                            for col_idx in custody_cols {
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
    fn check_hot_state_summary_diff_consistency(
        &self,
        _split: &Split,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let anchor_slot = self.get_anchor_info().anchor_slot;

        // Collect all summary slots and their strategies in a first pass.
        let mut summary_slots = HashSet::new();
        let mut base_slot_refs = Vec::new();

        for res in self
            .hot_db
            .iter_column::<Hash256>(DBColumn::BeaconStateHotSummary)
        {
            let (state_root, value) = res?;
            let summary = HotStateSummary::from_ssz_bytes(&value)?;
            result.inc_checks();

            summary_slots.insert(summary.slot);

            let strategy = self.hierarchy.storage_strategy(summary.slot, anchor_slot)?;

            match strategy {
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
                    base_slot_refs.push((summary.slot, base_slot));
                }
                StorageStrategy::ReplayFrom(base_slot) => {
                    base_slot_refs.push((summary.slot, base_slot));
                }
            }
        }

        // Verify that all DiffFrom/ReplayFrom base slots reference existing summaries.
        for (slot, base_slot) in base_slot_refs {
            result.inc_checks();
            if !summary_slots.contains(&base_slot) {
                result.add_violation(InvariantViolation::HotStateBaseSummaryMissing {
                    slot,
                    base_slot,
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
            result.inc_checks();

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
    fn check_state_cache_consistency(&self) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let state_roots = self.state_cache.lock().state_roots();

        for state_root in state_roots {
            result.inc_checks();

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
            result.inc_checks();

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
    ///
    /// Checks both directions:
    /// - **Forward**: every slot in the expected range has a state root entry.
    /// - **Reverse**: every existing state root entry has a valid cold state summary with
    ///   matching slot.
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
                result.inc_checks();

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
    fn check_cold_state_diff_consistency(
        &self,
        _split: &Split,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let mut summary_slots = HashSet::new();
        let mut base_slot_refs = Vec::new();

        for res in self
            .cold_db
            .iter_column::<Hash256>(DBColumn::BeaconColdStateSummary)
        {
            let (state_root, value) = res?;
            let summary = ColdStateSummary::from_ssz_bytes(&value)?;
            result.inc_checks();

            summary_slots.insert(summary.slot);

            let strategy = self
                .hierarchy
                .storage_strategy(summary.slot, Slot::new(0))?;

            let slot_bytes = summary.slot.as_u64().to_be_bytes();

            match strategy {
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
            result.inc_checks();
            if !summary_slots.contains(&base_slot) {
                result.add_violation(InvariantViolation::ColdStateBaseSummaryMissing {
                    slot,
                    base_slot,
                });
            }
        }

        Ok(result)
    }
}
