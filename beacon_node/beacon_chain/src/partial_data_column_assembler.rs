use lru::LruCache;
use parking_lot::RwLock;
use parking_lot::lock_api::RwLockReadGuard;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use types::partial_data_column_sidecar::{PartialDataColumn, PartialDataColumnHeader};
use types::{ColumnIndex, DataColumnSidecar, EthSpec, Hash256};

/// Assembles partial data columns into complete columns
pub struct PartialDataColumnAssembler<E: EthSpec> {
    /// Cache of assemblies keyed by block root
    assemblies: RwLock<LruCache<Hash256, PartialAssembly<E>>>,
}

/// Tracks partial columns being assembled for a single block
struct PartialAssembly<E: EthSpec> {
    header: PartialDataColumnHeader<E>,
    /// Map of column_index -> partial column being assembled
    columns: HashMap<ColumnIndex, Arc<PartialDataColumn<E>>>,
}

/// Result of merging a partial column
pub struct PartialMergeResult<E: EthSpec> {
    /// Merge that completed the column
    pub full_columns: Vec<Arc<DataColumnSidecar<E>>>,
    /// The updated partials for publishing
    pub updated_partials: Vec<Arc<PartialDataColumn<E>>>,
}

impl<E: EthSpec> PartialDataColumnAssembler<E> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            assemblies: RwLock::new(LruCache::new(capacity)),
        }
    }

    pub fn init<T>(&self, block_root: Hash256, header: T) -> Result<bool, T::Error>
    where
        T: TryInto<PartialDataColumnHeader<E>>,
    {
        let assemblies = self.assemblies.write();

        if assemblies.contains(&block_root) {
            return Ok(false);
        }

        let header = header.try_into()?;

        let assembly = PartialAssembly {
            header,
            columns: HashMap::new(),
        };

        self.assemblies.write().put(block_root, assembly);

        Ok(true)
    }

    /// Merge a received partial column into the assembly.
    /// Returns the merge result indicating if column is now complete.
    pub fn merge_partials(
        &self,
        block_root: Hash256,
        partials: Vec<PartialDataColumn<E>>,
    ) -> Option<PartialMergeResult<E>> {
        let mut assemblies = self.assemblies.write();
        let assembly = assemblies
            .try_get_or_insert_mut(block_root, || {
                partials
                    .iter()
                    .filter_map(|partial| partial.sidecar.header.first())
                    .next()
                    .map(|header| PartialAssembly {
                        header: header.clone(),
                        columns: HashMap::new(),
                    })
                    .ok_or(())
            })
            .ok()?;

        let mut full_columns = Vec::new();
        let mut updated_partials = Vec::new();

        for partial in partials {
            let column_index = partial.index;

            let merged = if let Some(existing) = assembly.columns.get(&column_index) {
                // Merge with existing partial
                let Some(merged_sidecar) = existing.sidecar.merge(&partial.sidecar) else {
                    continue;
                };
                PartialDataColumn {
                    block_root: existing.block_root,
                    index: existing.index,
                    sidecar: merged_sidecar,
                }
            } else {
                // First time seeing this column index for this block
                partial
            };

            // Check if merged column is now complete by trying to convert into full
            if let Some(full_column) = merged.try_clone_full() {
                full_columns.push(Arc::new(full_column));
            }

            // Update assembly with merged partial
            let merged = Arc::new(merged);
            assembly.columns.insert(column_index, merged.clone());
            updated_partials.push(merged);
        }

        Some(PartialMergeResult {
            full_columns,
            updated_partials,
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

    /// Get header for a block if we have an active assembly
    pub fn get_header(
        &self,
        block_root: &Hash256,
    ) -> Option<impl Deref<Target = PartialDataColumnHeader<E>>> {
        RwLockReadGuard::try_map(self.assemblies.read(), |assemblies| {
            assemblies.peek(block_root).map(|a| &a.header)
        })
        .ok()
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
            if assembly
                .header
                .signed_block_header
                .message
                .slot
                .epoch(E::slots_per_epoch())
                < cutoff_epoch
            {
                to_remove.push(*root);
            }
        }

        for root in to_remove {
            assemblies.pop(&root);
        }
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
