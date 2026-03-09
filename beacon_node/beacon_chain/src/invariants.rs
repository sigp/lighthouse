//! Beacon chain database invariant checks.
//!
//! This module extends the store-level invariant checks with additional checks that require
//! access to fork choice, state cache, and other beacon chain components.
//!
//! See: https://hackmd.io/@sproul/database-invariants

use crate::BeaconChain;
use crate::beacon_chain::BeaconChainTypes;
use store::DBColumn;
use store::KeyValueStore;
use store::invariants::{InvariantCheckResult, InvariantViolation};
use types::*;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Run all database invariant checks, including those requiring fork choice and state cache.
    ///
    /// This is the top-level entry point that checks all 12 invariants from:
    /// https://hackmd.io/@sproul/database-invariants
    ///
    /// Invariants 2-4, 10-12 are checked at the store level via `HotColdDB::check_invariants`.
    /// Invariants 1, 5-9 are checked here at the beacon chain level.
    pub fn check_database_invariants(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = self.store.check_invariants()?;

        result.merge(self.check_fork_choice_block_consistency());
        result.merge(self.check_execution_payload_consistency()?);
        result.merge(self.check_blob_consistency()?);
        result.merge(self.check_data_column_consistency()?);
        result.merge(self.check_state_cache_consistency()?);
        result.merge(self.check_pubkey_cache_consistency()?);

        Ok(result)
    }

    /// Invariant 1 (Hot DB): Fork choice block consistency.
    ///
    /// ```text
    /// block in fork_choice -> block in hot_db
    /// ```
    ///
    /// Every block tracked by the fork choice proto-array must exist in the hot database.
    /// This ensures the fork choice tree never references blocks that have been pruned or lost.
    fn check_fork_choice_block_consistency(&self) -> InvariantCheckResult {
        let mut result = InvariantCheckResult::new();
        let invariant_name = "fork_choice_block_consistency";

        // Collect block roots from fork choice under the read lock, then drop the lock before
        // performing DB I/O to avoid blocking fork choice writes (recompute_head).
        let block_roots: Vec<(Hash256, Slot)> = {
            let fc = self.canonical_head.fork_choice_read_lock();
            let proto_array = fc.proto_array().core_proto_array();
            proto_array
                .nodes
                .iter()
                .map(|node| (node.root, node.slot))
                .collect()
        };

        for (block_root, slot) in block_roots {
            result.inc_checks();

            match self
                .store
                .hot_db
                .key_exists(DBColumn::BeaconBlock, block_root.as_slice())
            {
                Ok(true) => {}
                Ok(false) => {
                    result.add_violation(InvariantViolation {
                        invariant: invariant_name.to_string(),
                        message: format!(
                            "block {block_root:?} at slot {slot} exists in fork choice \
                             but not in hot DB",
                        ),
                    });
                }
                Err(e) => {
                    result.add_violation(InvariantViolation {
                        invariant: invariant_name.to_string(),
                        message: format!(
                            "error checking block {block_root:?} existence in hot DB: {e:?}"
                        ),
                    });
                }
            }
        }

        result
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
    fn check_execution_payload_consistency(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = InvariantCheckResult::new();
        let invariant_name = "execution_payload_consistency";

        if self.store.get_config().prune_payloads {
            return Ok(result);
        }

        let bellatrix_fork_slot = match self.spec.bellatrix_fork_epoch {
            Some(epoch) => epoch.start_slot(T::EthSpec::slots_per_epoch()),
            None => return Ok(result),
        };

        for res in self
            .store
            .hot_db
            .iter_column_keys::<Hash256>(DBColumn::BeaconBlock)
        {
            let block_root = res?;

            let Some(block) = self.store.get_blinded_block(&block_root)? else {
                continue;
            };

            // Only post-merge blocks have execution payloads.
            if block.slot() < bellatrix_fork_slot {
                continue;
            }

            result.inc_checks();

            let has_payload = self.store.execution_payload_exists(&block_root)?;
            if !has_payload {
                // Post-Gloas blocks store a payload envelope instead.
                let has_envelope = self.store.payload_envelope_exists(&block_root)?;
                if !has_envelope {
                    result.add_violation(InvariantViolation {
                        invariant: invariant_name.to_string(),
                        message: format!(
                            "block {block_root:?} at slot {} has no execution payload \
                             or payload envelope (prune_payloads=false)",
                            block.slot()
                        ),
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
    fn check_blob_consistency(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = InvariantCheckResult::new();
        let invariant_name = "blob_consistency";

        let deneb_fork_slot = match self.spec.deneb_fork_epoch {
            Some(epoch) => epoch.start_slot(T::EthSpec::slots_per_epoch()),
            None => return Ok(result),
        };

        // Post-Fulu blocks use data columns, not blobs.
        let fulu_fork_slot = self
            .spec
            .fulu_fork_epoch
            .map(|epoch| epoch.start_slot(T::EthSpec::slots_per_epoch()));

        let blob_info = self.store.get_blob_info();
        let oldest_blob_slot = match blob_info.oldest_blob_slot {
            Some(slot) => slot,
            None => return Ok(result),
        };

        for res in self
            .store
            .hot_db
            .iter_column_keys::<Hash256>(DBColumn::BeaconBlock)
        {
            let block_root = res?;

            let Some(block) = self.store.get_blinded_block(&block_root)? else {
                continue;
            };

            let slot = block.slot();

            // Only check Deneb+ blocks within blob availability, excluding Fulu+ blocks.
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
                .store
                .blobs_db
                .key_exists(DBColumn::BeaconBlob, block_root.as_slice())?;

            if !has_blob_entry {
                result.add_violation(InvariantViolation {
                    invariant: invariant_name.to_string(),
                    message: format!(
                        "block {block_root:?} at slot {slot} has no blob sidecar entry",
                    ),
                });
            }
        }

        Ok(result)
    }

    /// Invariant 7 (Hot DB): Data column consistency (post-Fulu).
    ///
    /// ```text
    /// block in hot_db && block.slot >= fulu_fork_slot
    ///   && block.slot >= oldest_data_column_slot
    ///   && data_column_idx in custody_columns
    ///   -> (block_root, data_column_idx) in blob_db
    /// ```
    ///
    /// Every post-Fulu block within data column availability should have all custody columns
    /// stored. Note: custody column requirements may vary by epoch, but this check uses the
    /// current head epoch's custody columns. Historical blocks may have had different custody
    /// requirements; see https://github.com/sigp/lighthouse/issues/6572.
    fn check_data_column_consistency(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = InvariantCheckResult::new();
        let invariant_name = "data_column_consistency";

        let fulu_fork_slot = match self.spec.fulu_fork_epoch {
            Some(epoch) => epoch.start_slot(T::EthSpec::slots_per_epoch()),
            None => return Ok(result),
        };

        let data_column_info = self.store.get_data_column_info();
        let oldest_data_column_slot = match data_column_info.oldest_data_column_slot {
            Some(slot) => slot,
            None => return Ok(result),
        };

        // Get custody columns for the current head epoch. Historical epochs may have different
        // requirements but we use the current set as an approximation.
        let custody_context = self.data_availability_checker.custody_context();
        let custody_columns: Vec<ColumnIndex> = custody_context
            .custody_columns_for_epoch(None, &self.spec)
            .to_vec();

        for res in self
            .store
            .hot_db
            .iter_column_keys::<Hash256>(DBColumn::BeaconBlock)
        {
            let block_root = res?;

            let Some(block) = self.store.get_blinded_block(&block_root)? else {
                continue;
            };

            if block.slot() < fulu_fork_slot || block.slot() < oldest_data_column_slot {
                continue;
            }

            result.inc_checks();

            let stored_columns = self.store.get_data_column_keys(block_root)?;
            for col_idx in &custody_columns {
                if !stored_columns.contains(col_idx) {
                    result.add_violation(InvariantViolation {
                        invariant: invariant_name.to_string(),
                        message: format!(
                            "block {block_root:?} at slot {} missing custody data column {col_idx}",
                            block.slot()
                        ),
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
    fn check_state_cache_consistency(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = InvariantCheckResult::new();
        let invariant_name = "state_cache_consistency";

        let state_roots = self.store.state_cache.lock().state_roots();

        for state_root in state_roots {
            result.inc_checks();

            let has_summary = self
                .store
                .hot_db
                .key_exists(DBColumn::BeaconStateHotSummary, state_root.as_slice())?;
            if !has_summary {
                result.add_violation(InvariantViolation {
                    invariant: invariant_name.to_string(),
                    message: format!(
                        "state {state_root:?} is in state cache but has no hot state summary"
                    ),
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
    /// The number of pubkeys in the in-memory validator pubkey cache should match the number
    /// stored on disk in the PubkeyCache column. This is a count-based check; individual
    /// pubkey values are not compared.
    fn check_pubkey_cache_consistency(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = InvariantCheckResult::new();
        let invariant_name = "pubkey_cache_consistency";

        result.inc_checks();

        let pubkey_cache = self.validator_pubkey_cache.read();
        let in_memory_count = pubkey_cache.len();

        let mut on_disk_count = 0usize;
        for res in self
            .store
            .hot_db
            .iter_column_keys::<Vec<u8>>(DBColumn::PubkeyCache)
        {
            let _ = res?;
            on_disk_count += 1;
        }

        if in_memory_count != on_disk_count {
            result.add_violation(InvariantViolation {
                invariant: invariant_name.to_string(),
                message: format!(
                    "pubkey cache has {in_memory_count} keys in memory \
                     but {on_disk_count} on disk"
                ),
            });
        }

        Ok(result)
    }
}
