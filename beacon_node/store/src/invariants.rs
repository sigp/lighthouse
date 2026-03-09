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
    /// Block root exists in BeaconBlock column but block failed to load.
    BlockFailedToLoad { block_root: Hash256 },
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
    /// Cold block root index has invalid byte length.
    ColdBlockRootInvalidLength { slot: Slot, length: usize },
    /// Cold block root index references a block not in hot DB.
    ColdBlockRootOrphan { slot: Slot, block_root: Hash256 },
    /// Cold state root index missing for a slot.
    ColdStateRootMissing {
        slot: Slot,
        state_lower_limit: Slot,
        state_upper_limit: Slot,
        split_slot: Slot,
    },
    /// Cold state root index has invalid key length.
    ColdStateRootInvalidKeyLength { length: usize },
    /// Cold state root index has invalid root length.
    ColdStateRootInvalidRootLength { slot: Slot, length: usize },
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
    pub fn check_invariants(&self) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();
        let split = self.get_split_info();

        result.merge(self.check_hot_block_state_consistency(&split)?);
        result.merge(self.check_hot_state_summary_diff_consistency(&split)?);
        result.merge(self.check_hot_state_summary_chain_consistency(&split)?);
        result.merge(self.check_execution_payload_consistency()?);
        result.merge(self.check_blob_consistency()?);
        result.merge(self.check_state_cache_consistency()?);
        result.merge(self.check_cold_block_root_indices(&split)?);
        result.merge(self.check_cold_state_root_indices(&split)?);
        result.merge(self.check_cold_state_diff_consistency(&split)?);

        Ok(result)
    }

    /// Invariant 2 (Hot DB): Block-state consistency.
    ///
    /// ```text
    /// block in hot_db && block.slot >= split.slot
    ///   -> state_summary for block.state_root() in hot_db
    /// ```
    ///
    /// Every block in the hot DB at or above the split should have a corresponding hot state
    /// summary. Blocks below the split are in the cold range and are not checked here.
    fn check_hot_block_state_consistency(
        &self,
        split: &Split,
    ) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        for res in self
            .hot_db
            .iter_column_keys::<Hash256>(DBColumn::BeaconBlock)
        {
            let block_root = res?;
            result.inc_checks();

            let Some(block) = self.get_blinded_block(&block_root)? else {
                result.add_violation(InvariantViolation::BlockFailedToLoad { block_root });
                continue;
            };

            if block.slot() >= split.slot {
                let state_root = block.state_root();
                let has_summary = self
                    .hot_db
                    .key_exists(DBColumn::BeaconStateHotSummary, state_root.as_slice())?;
                if !has_summary {
                    result.add_violation(InvariantViolation::HotBlockMissingStateSummary {
                        block_root,
                        slot: block.slot(),
                        state_root,
                    });
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

        for res in self
            .hot_db
            .iter_column::<Hash256>(DBColumn::BeaconStateHotSummary)
        {
            let (state_root, value) = res?;
            let summary = HotStateSummary::from_ssz_bytes(&value)?;
            result.inc_checks();

            let strategy = match self.hierarchy.storage_strategy(summary.slot, anchor_slot) {
                Ok(s) => s,
                Err(crate::hdiff::Error::LessThanStart(_, _)) => {
                    // States with slot < anchor_slot are expected during checkpoint sync before
                    // backfill completes. Skip these rather than treating them as violations.
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

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
                StorageStrategy::DiffFrom(_base_slot) => {
                    let has_diff = self
                        .hot_db
                        .key_exists(DBColumn::BeaconStateHotDiff, state_root.as_slice())?;
                    if !has_diff {
                        result.add_violation(InvariantViolation::HotStateMissingDiff {
                            state_root,
                            slot: summary.slot,
                        });
                    }
                }
                StorageStrategy::ReplayFrom(_) => {
                    // ReplayFrom means no diff or snapshot is stored; just the summary.
                }
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

    /// Invariant 5 (Hot DB): Execution payload consistency.
    ///
    /// ```text
    /// block in hot_db && !prune_payloads
    ///   -> execution payload or payload envelope for block.root in hot_db
    /// ```
    ///
    /// When payload pruning is disabled, every post-Bellatrix block should have its execution
    /// payload (pre-Gloas) or payload envelope (post-Gloas) stored. When `prune_payloads` is
    /// true (the default), payloads are pruned at finalization and this check is skipped.
    fn check_execution_payload_consistency(&self) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        if self.get_config().prune_payloads {
            return Ok(result);
        }

        let bellatrix_fork_slot = match self.spec.bellatrix_fork_epoch {
            Some(epoch) => epoch.start_slot(E::slots_per_epoch()),
            None => return Ok(result),
        };

        for res in self
            .hot_db
            .iter_column_keys::<Hash256>(DBColumn::BeaconBlock)
        {
            let block_root = res?;

            let Some(block) = self.get_blinded_block(&block_root)? else {
                result.add_violation(InvariantViolation::BlockFailedToLoad { block_root });
                continue;
            };

            if block.slot() < bellatrix_fork_slot {
                continue;
            }

            result.inc_checks();

            let has_payload = self.execution_payload_exists(&block_root)?;
            if !has_payload {
                let has_envelope = self.payload_envelope_exists(&block_root)?;
                if !has_envelope {
                    result.add_violation(InvariantViolation::ExecutionPayloadMissing {
                        block_root,
                        slot: block.slot(),
                    });
                }
            }
        }

        Ok(result)
    }

    /// Invariant 6 (Hot DB): Blob sidecar consistency (Deneb to Fulu).
    ///
    /// ```text
    /// block in hot_db && block.slot >= deneb_fork_slot && block.slot < fulu_fork_slot
    ///   && block.slot >= oldest_blob_slot
    ///   -> blob sidecar list for block.root in blob_db
    /// ```
    ///
    /// Every post-Deneb, pre-Fulu block within the blob availability window should have a blob
    /// sidecar entry (which may be an empty list for blocks with no blobs). Post-Fulu blocks
    /// use data columns instead of blobs and are checked by invariant 7.
    fn check_blob_consistency(&self) -> Result<InvariantCheckResult, Error> {
        let mut result = InvariantCheckResult::new();

        let deneb_fork_slot = match self.spec.deneb_fork_epoch {
            Some(epoch) => epoch.start_slot(E::slots_per_epoch()),
            None => return Ok(result),
        };

        let fulu_fork_slot = self
            .spec
            .fulu_fork_epoch
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()));

        let blob_info = self.get_blob_info();
        let Some(oldest_blob_slot) = blob_info.oldest_blob_slot else {
            return Ok(result);
        };

        for res in self
            .hot_db
            .iter_column_keys::<Hash256>(DBColumn::BeaconBlock)
        {
            let block_root = res?;

            let Some(block) = self.get_blinded_block(&block_root)? else {
                result.add_violation(InvariantViolation::BlockFailedToLoad { block_root });
                continue;
            };

            let slot = block.slot();

            if slot < deneb_fork_slot || slot < oldest_blob_slot {
                continue;
            }
            if let Some(fulu_slot) = fulu_fork_slot
                && slot >= fulu_slot
            {
                continue;
            }

            result.inc_checks();

            let has_blob_entry = self
                .blobs_db
                .key_exists(DBColumn::BeaconBlob, block_root.as_slice())?;

            if !has_blob_entry {
                result.add_violation(InvariantViolation::BlobSidecarMissing { block_root, slot });
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
        let start_slot = anchor_info.oldest_block_slot;

        if start_slot >= split.slot {
            return Ok(result);
        }

        for slot_val in start_slot.as_u64()..split.slot.as_u64() {
            let slot = Slot::new(slot_val);
            result.inc_checks();

            let slot_bytes = slot_val.to_be_bytes();
            let block_root_bytes = self
                .cold_db
                .get_bytes(DBColumn::BeaconBlockRoots, &slot_bytes)?;

            match block_root_bytes {
                Some(root_bytes) => {
                    if root_bytes.len() == 32 {
                        let block_root = Hash256::from_slice(&root_bytes);
                        let block_exists = self
                            .hot_db
                            .key_exists(DBColumn::BeaconBlock, block_root.as_slice())?;
                        if !block_exists {
                            result.add_violation(InvariantViolation::ColdBlockRootOrphan {
                                slot,
                                block_root,
                            });
                        }
                    } else {
                        result.add_violation(InvariantViolation::ColdBlockRootInvalidLength {
                            slot,
                            length: root_bytes.len(),
                        });
                    }
                }
                None => {
                    result.add_violation(InvariantViolation::ColdBlockRootMissing {
                        slot,
                        oldest_block_slot: start_slot,
                        split_slot: split.slot,
                    });
                }
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

        // Forward check: verify that every expected slot has a state root entry.
        //
        // Expected slots are: (i <= state_lower_limit || i >= effective_upper) && i < split.slot
        // where effective_upper = min(split.slot, state_upper_limit).
        let state_lower = anchor_info.state_lower_limit;
        let effective_upper = cmp::min(split.slot, anchor_info.state_upper_limit);

        for slot_val in 0..split.slot.as_u64() {
            let slot = Slot::new(slot_val);

            if slot <= state_lower || slot >= effective_upper {
                result.inc_checks();
                let slot_bytes = slot_val.to_be_bytes();
                let has_entry = self
                    .cold_db
                    .key_exists(DBColumn::BeaconStateRoots, &slot_bytes)?;
                if !has_entry {
                    result.add_violation(InvariantViolation::ColdStateRootMissing {
                        slot,
                        state_lower_limit: state_lower,
                        state_upper_limit: anchor_info.state_upper_limit,
                        split_slot: split.slot,
                    });
                }
            }
        }

        // Reverse check: verify every existing state root entry has a valid summary.
        for res in self
            .cold_db
            .iter_column::<Vec<u8>>(DBColumn::BeaconStateRoots)
        {
            let (slot_bytes, root_bytes) = res?;
            result.inc_checks();

            if slot_bytes.len() != 8 {
                result.add_violation(InvariantViolation::ColdStateRootInvalidKeyLength {
                    length: slot_bytes.len(),
                });
                continue;
            }

            let slot_val = u64::from_be_bytes(slot_bytes.try_into().map_err(|_| {
                Error::InvalidKey("cold state root index key conversion failed".to_string())
            })?);
            let slot = Slot::new(slot_val);

            if root_bytes.len() != 32 {
                result.add_violation(InvariantViolation::ColdStateRootInvalidRootLength {
                    slot,
                    length: root_bytes.len(),
                });
                continue;
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

        for res in self
            .cold_db
            .iter_column::<Hash256>(DBColumn::BeaconColdStateSummary)
        {
            let (state_root, value) = res?;
            let summary = ColdStateSummary::from_ssz_bytes(&value)?;
            result.inc_checks();

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
                StorageStrategy::DiffFrom(_) => {
                    let has_diff = self
                        .cold_db
                        .key_exists(DBColumn::BeaconStateDiff, &slot_bytes)?;
                    if !has_diff {
                        result.add_violation(InvariantViolation::ColdStateMissingDiff {
                            state_root,
                            slot: summary.slot,
                        });
                    }
                }
                StorageStrategy::ReplayFrom(_) => {
                    // No diff or snapshot needed.
                }
            }
        }

        Ok(result)
    }
}
