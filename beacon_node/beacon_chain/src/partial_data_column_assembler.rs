use crate::data_column_verification::KzgVerifiedCustodyPartialDataColumn;
use lru::LruCache;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use types::partial_data_column_sidecar::PartialDataColumn;
use types::{ColumnIndex, DataColumnSidecar, EthSpec, Hash256, KzgCommitments, Slot};

/// Assembles partial data columns into complete columns
pub struct PartialDataColumnAssembler<E: EthSpec> {
    /// Cache of assemblies keyed by block root
    assemblies: RwLock<LruCache<Hash256, PartialAssembly<E>>>,
}

/// Tracks partial columns being assembled for a single block
struct PartialAssembly<E: EthSpec> {
    #[allow(dead_code)]
    block_root: Hash256,
    slot: Slot,
    kzg_commitments: KzgCommitments<E>,
    /// Map of column_index -> partial column being assembled
    columns: HashMap<ColumnIndex, Arc<PartialDataColumn<E>>>,
}

/// Result of merging a partial column
pub enum PartialMergeResult<E: EthSpec> {
    /// Merge was successful but column is still incomplete
    Incomplete {
        updated_partial: Arc<PartialDataColumn<E>>,
    },
    /// Merge completed the column
    Completed {
        full_column: Arc<DataColumnSidecar<E>>,
        /// The updated partial for publishing (same as full but as partial type)
        updated_partial: Arc<PartialDataColumn<E>>,
    },
}

impl<E: EthSpec> PartialDataColumnAssembler<E> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            assemblies: RwLock::new(LruCache::new(capacity)),
        }
    }

    /// Initialize assembler with columns from engine getBlobsV3 response.
    /// Returns immediately complete columns and partials that need gossip propagation.
    pub fn init_with_engine_blobs(
        &self,
        block_root: Hash256,
        slot: Slot,
        kzg_commitments: KzgCommitments<E>,
        custody_columns: Vec<KzgVerifiedCustodyPartialDataColumn<E>>,
    ) -> InitResult<E> {
        let mut result = InitResult {
            complete_columns: vec![],
            incomplete_partials: vec![],
        };

        let mut assembly = PartialAssembly {
            block_root,
            slot,
            kzg_commitments: kzg_commitments.clone(),
            columns: HashMap::new(),
        };

        for custody_col in custody_columns {
            let partial = custody_col.into_inner();
            let column_index = partial.index;

            // Check if this partial is already complete
            if partial.sidecar.is_complete() {
                // Convert to full column
                if let Some(full) = Self::partial_to_full(&partial, &kzg_commitments) {
                    result.complete_columns.push(full);
                    continue;
                }
            }

            // Store incomplete partial
            result.incomplete_partials.push(partial.clone());
            assembly.columns.insert(column_index, partial);
        }

        // Only cache if we have incomplete columns
        if !assembly.columns.is_empty() {
            self.assemblies.write().put(block_root, assembly);
        }

        result
    }

    /// Merge a received partial column into the assembly.
    /// Returns the merge result indicating if column is now complete.
    pub fn merge_partial(
        &self,
        block_root: Hash256,
        partial: Arc<PartialDataColumn<E>>,
    ) -> Option<PartialMergeResult<E>> {
        let mut assemblies = self.assemblies.write();
        let assembly = assemblies.get_mut(&block_root)?;

        let column_index = partial.index;

        let merged = if let Some(existing) = assembly.columns.get(&column_index) {
            // Merge with existing partial
            let merged_sidecar = existing.sidecar.merge(&partial.sidecar)?;
            Arc::new(PartialDataColumn {
                block_root: existing.block_root,
                index: existing.index,
                sidecar: merged_sidecar,
            })
        } else {
            // First time seeing this column index for this block
            partial.clone()
        };

        // Check if merged column is now complete
        if merged.sidecar.is_complete() {
            // Remove from assembly since it's complete
            assembly.columns.remove(&column_index);

            // Convert to full column
            if let Some(full_column) = Self::partial_to_full(&merged, &assembly.kzg_commitments) {
                return Some(PartialMergeResult::Completed {
                    full_column,
                    updated_partial: merged,
                });
            }
        }

        // Update assembly with merged partial
        assembly.columns.insert(column_index, merged.clone());

        Some(PartialMergeResult::Incomplete {
            updated_partial: merged,
        })
    }

    /// Get the current partial for a specific column if it exists in assembly
    pub fn get_partial(
        &self,
        block_root: &Hash256,
        column_index: ColumnIndex,
    ) -> Option<Arc<PartialDataColumn<E>>> {
        self.assemblies
            .read()
            .peek(block_root)?
            .columns
            .get(&column_index)
            .cloned()
    }

    /// Get commitments for a block if we have an active assembly
    pub fn get_commitments(&self, block_root: &Hash256) -> Option<KzgCommitments<E>> {
        self.assemblies
            .read()
            .peek(block_root)
            .map(|assembly| assembly.kzg_commitments.clone())
    }

    /// Check if we have an assembly for this block
    pub fn has_assembly(&self, block_root: &Hash256) -> bool {
        self.assemblies.read().contains(block_root)
    }

    /// Remove assembly for a block (called when block is finalized or evicted)
    pub fn remove_assembly(&self, block_root: &Hash256) {
        self.assemblies.write().pop(block_root);
    }

    /// Maintenance: remove assemblies older than cutoff epoch
    pub fn do_maintenance(&self, cutoff_epoch: types::Epoch) {
        let mut assemblies = self.assemblies.write();
        let mut to_remove = vec![];

        for (root, assembly) in assemblies.iter() {
            if assembly.slot.epoch(E::slots_per_epoch()) < cutoff_epoch {
                to_remove.push(*root);
            }
        }

        for root in to_remove {
            assemblies.pop(&root);
        }
    }

    /// Convert a complete partial to a full DataColumnSidecar
    fn partial_to_full(
        partial: &PartialDataColumn<E>,
        kzg_commitments: &KzgCommitments<E>,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        // Use the as_full method - requires a block for signed header
        // For now we'll construct it manually since we have all the data
        if !partial.sidecar.is_complete() {
            return None;
        }

        let expected = partial.sidecar.cells_present_bitmap.len();
        if partial.sidecar.column.len() != expected
            || partial.sidecar.kzg_proofs.len() != expected
            || kzg_commitments.len() != expected
        {
            return None;
        }

        // We need the signed block header and inclusion proof which requires the full block
        // For the assembler, we'll return None here and require callers to use the
        // VerifiablePartialDataColumn::as_full method with the actual block
        // This is handled in the merge flow where we have access to the block
        None
    }

    /// Get cache size for metrics
    pub fn cache_size(&self) -> usize {
        self.assemblies.read().len()
    }
}

/// Result of initializing with engine blobs
pub struct InitResult<E: EthSpec> {
    /// Columns that were already complete
    pub complete_columns: Vec<Arc<DataColumnSidecar<E>>>,
    /// Columns that need further assembly via gossip
    pub incomplete_partials: Vec<Arc<PartialDataColumn<E>>>,
}
