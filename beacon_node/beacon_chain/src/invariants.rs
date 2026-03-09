//! Beacon chain database invariant checks.
//!
//! This module extends the store-level invariant checks with additional checks that require
//! access to fork choice, data availability checker, and validator pubkey cache.
//!
//! See `BeaconChain::check_database_invariants` for the full list.

use crate::BeaconChain;
use crate::beacon_chain::BeaconChainTypes;
use store::DBColumn;
use store::KeyValueStore;
use store::invariants::{InvariantCheckResult, InvariantViolation};
use types::*;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Run all database invariant checks, including those requiring fork choice and state cache.
    ///
    /// This is the top-level entry point that checks all 12 database invariants.
    ///
    /// Invariants 2-6, 8, 10-12 are checked at the store level via `HotColdDB::check_invariants`.
    /// Invariants 1, 7, 9 are checked here at the beacon chain level.
    pub fn check_database_invariants(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = self.store.check_invariants()?;

        result.merge(self.check_fork_choice_block_consistency()?);
        result.merge(self.check_data_column_consistency()?);
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
    fn check_fork_choice_block_consistency(&self) -> Result<InvariantCheckResult, store::Error> {
        let mut result = InvariantCheckResult::new();

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

            let exists = self
                .store
                .hot_db
                .key_exists(DBColumn::BeaconBlock, block_root.as_slice())?;

            if !exists {
                result
                    .add_violation(InvariantViolation::ForkChoiceBlockMissing { block_root, slot });
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

        let fulu_fork_slot = match self.spec.fulu_fork_epoch {
            Some(epoch) => epoch.start_slot(T::EthSpec::slots_per_epoch()),
            None => return Ok(result),
        };

        let data_column_info = self.store.get_data_column_info();
        let Some(oldest_data_column_slot) = data_column_info.oldest_data_column_slot else {
            return Ok(result);
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
                    result.add_violation(InvariantViolation::DataColumnMissing {
                        block_root,
                        slot: block.slot(),
                        column_index: *col_idx,
                    });
                }
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
            result.add_violation(InvariantViolation::PubkeyCacheCountMismatch {
                in_memory: in_memory_count,
                on_disk: on_disk_count,
            });
        }

        Ok(result)
    }
}
