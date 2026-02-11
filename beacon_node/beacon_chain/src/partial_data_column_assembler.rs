use crate::data_column_verification::{
    KzgVerifiedCustodyDataColumn, KzgVerifiedCustodyPartialDataColumn,
};
use lru::LruCache;
use parking_lot::RwLock;
use parking_lot::lock_api::RwLockReadGuard;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use types::data::{ColumnIndex, DataColumnSidecar, PartialDataColumn, PartialDataColumnHeader};
use types::{DataColumnSidecarFulu, EthSpec, Hash256};

/// Assembles partial data columns into complete columns
pub struct PartialDataColumnAssembler<E: EthSpec> {
    /// Cache of assemblies keyed by block root
    assemblies: RwLock<LruCache<Hash256, PartialAssembly<E>>>,
}

/// Tracks partial columns being assembled for a single block
struct PartialAssembly<E: EthSpec> {
    header: PartialDataColumnHeader<E>,
    has_local_blobs: bool,
    /// Map of column_index -> partial column being assembled
    columns: HashMap<ColumnIndex, AssemblyColumn<E>>,
}

#[derive(Clone, Debug)]
pub enum AssemblyColumn<E: EthSpec> {
    Complete,
    Incomplete(KzgVerifiedCustodyPartialDataColumn<E>),
}

/// Result of merging a partial column
pub struct PartialMergeResult<E: EthSpec> {
    /// How many cells were added to the store
    pub added_cells: usize,
    /// Have local blobs been added yet
    pub local_blobs: bool,
    /// Merge that completed the column
    pub full_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
    /// The updated partials for publishing
    pub updated_partials: Vec<KzgVerifiedCustodyPartialDataColumn<E>>,
}

impl<E: EthSpec> PartialDataColumnAssembler<E> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            assemblies: RwLock::new(LruCache::new(capacity)),
        }
    }

    /// Returns true unless the header was already contained or the passed argument failed to convert to a header
    pub fn init<T>(&self, block_root: Hash256, header: T) -> bool
    where
        T: TryInto<PartialDataColumnHeader<E>>,
    {
        let mut assemblies = self.assemblies.write();

        if assemblies.contains(&block_root) {
            return false;
        }

        let Ok(header) = header.try_into() else {
            return false;
        };

        let assembly = PartialAssembly {
            header,
            has_local_blobs: false,
            columns: HashMap::new(),
        };

        assemblies.put(block_root, assembly);

        true
    }

    /// Merge a received partial column into the assembly.
    /// Returns the merge result indicating if column is now complete.
    pub fn merge_partials(
        &self,
        block_root: Hash256,
        partials: Vec<KzgVerifiedCustodyPartialDataColumn<E>>,
        local_blobs: bool,
    ) -> Option<PartialMergeResult<E>> {
        let mut assemblies = self.assemblies.write();
        let assembly = assemblies
            .try_get_or_insert_mut(block_root, || {
                partials
                    .iter()
                    .filter_map(|partial| partial.as_data_column().sidecar.header.first())
                    .next()
                    .map(|header| PartialAssembly {
                        header: header.clone(),
                        has_local_blobs: local_blobs,
                        columns: HashMap::new(),
                    })
                    .ok_or(())
            })
            .ok()?;

        let mut full_columns = Vec::new();
        let mut updated_partials = Vec::new();
        let mut added_cells = 0;

        for partial in partials {
            let partial_column = partial.as_data_column();
            let column_index = partial_column.index;

            let merged = if let Some(existing) = assembly.columns.get(&column_index) {
                let AssemblyColumn::Incomplete(existing) = existing else {
                    // Already complete.
                    continue;
                };
                let column = existing.as_data_column();

                let old_len = column.sidecar.column.len();

                // Merge with existing partial
                let Some(merged) = existing.merge(&partial) else {
                    continue;
                };

                let adding_cells = merged
                    .as_data_column()
                    .sidecar
                    .column
                    .len()
                    .saturating_sub(old_len);

                added_cells += adding_cells;

                if adding_cells == 0 {
                    continue;
                }

                merged
            } else {
                added_cells += partial_column.sidecar.column.len();
                // First time seeing this column index for this block
                partial
            };

            // Check if merged column is now complete by trying to convert into full
            let column = if let Some(full_column) = merged.try_clone_full() {
                full_columns.push(full_column);
                AssemblyColumn::Complete
            } else {
                AssemblyColumn::Incomplete(merged.clone())
            };

            // Update assembly with merged partial
            assembly.columns.insert(column_index, column);
            updated_partials.push(merged);
        }

        if local_blobs {
            assembly.has_local_blobs = true;
        }

        Some(PartialMergeResult {
            added_cells,
            local_blobs: assembly.has_local_blobs,
            full_columns,
            updated_partials,
        })
    }

    /// Mark a column as assembled. Returns true if the column was previously incomplete or not
    /// in the assembly at all.
    pub fn mark_as_complete(&self, block_root: Hash256, column: &DataColumnSidecarFulu<E>) -> bool {
        let mut assemblies = self.assemblies.write();
        let assembly = assemblies.get_or_insert_mut(block_root, || PartialAssembly {
            header: PartialDataColumnHeader {
                kzg_commitments: column.kzg_commitments.clone(),
                signed_block_header: column.signed_block_header.clone(),
                kzg_commitments_inclusion_proof: column.kzg_commitments_inclusion_proof.clone(),
            },
            has_local_blobs: false,
            columns: Default::default(),
        });
        let prev = assembly
            .columns
            .insert(column.index, AssemblyColumn::Complete);
        !matches!(prev, Some(AssemblyColumn::Complete))
    }

    /// Get the current partial for a specific column if it exists in assembly
    pub fn get_partial(
        &self,
        block_root: &Hash256,
        column_index: ColumnIndex,
    ) -> Option<AssemblyColumn<E>> {
        self.assemblies
            .read()
            .peek(block_root)?
            .columns
            .get(&column_index)
            .cloned()
    }

    /// Get all current partials for a block
    pub fn get_partials(
        &self,
        block_root: &Hash256,
    ) -> Option<Vec<KzgVerifiedCustodyPartialDataColumn<E>>> {
        Some(
            self.assemblies
                .read()
                .peek(block_root)?
                .columns
                .values()
                .filter_map(|value| {
                    if let AssemblyColumn::Incomplete(partial) = value {
                        Some(partial.clone())
                    } else {
                        None
                    }
                })
                .collect(),
        )
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
}

/// Result of initializing with engine blobs
pub struct InitResult<E: EthSpec> {
    /// Columns that were already complete
    pub complete_columns: Vec<Arc<DataColumnSidecar<E>>>,
    /// Columns that need further assembly via gossip
    pub incomplete_partials: Vec<Arc<PartialDataColumn<E>>>,
}
