use crate::data_column_verification::{
    KzgVerifiedCustodyDataColumn, KzgVerifiedCustodyPartialDataColumn,
};
use hashlink::lru_cache::LruCache;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;
use types::core::{Epoch, EthSpec, Hash256};
use types::data::{ColumnIndex, PartialDataColumnHeader};

/// Assembles partial data columns into complete columns
pub struct PartialDataColumnAssembler<E: EthSpec> {
    /// Cache of assemblies keyed by block root
    assemblies: RwLock<LruCache<Hash256, PartialAssembly<E>>>,
}

/// Tracks partial columns being assembled for a single block
struct PartialAssembly<E: EthSpec> {
    header: Arc<PartialDataColumnHeader<E>>,
    has_local_blobs: bool,
    /// Map of column_index -> partial column being assembled
    columns: HashMap<ColumnIndex, AssemblyColumn<E>>,
}

#[derive(Clone, Debug)]
pub enum AssemblyColumn<E: EthSpec> {
    // As the actual column is Arc'd inside, storing it redundantly here will not increase memory usage.
    Complete(KzgVerifiedCustodyDataColumn<E>),
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
    pub fn new(capacity: usize) -> Self {
        Self {
            assemblies: RwLock::new(LruCache::new(capacity)),
        }
    }

    /// Insert a `header` for the given `block_root` into the assembler.
    /// Returns true unless there already is a header for the block root.
    pub fn init(&self, block_root: Hash256, header: Arc<PartialDataColumnHeader<E>>) -> bool {
        let mut assemblies = self.assemblies.write();

        if assemblies.contains_key(&block_root) {
            return false;
        }

        let assembly = PartialAssembly {
            header,
            has_local_blobs: false,
            columns: HashMap::new(),
        };

        assemblies.insert(block_root, assembly);

        true
    }

    /// Merge one or more received partial columns into the assembly.
    /// Returns the merge result indicating if the columns are now complete.
    pub fn merge_partials(
        &self,
        block_root: Hash256,
        partials: Vec<KzgVerifiedCustodyPartialDataColumn<E>>,
        header: Arc<PartialDataColumnHeader<E>>,
    ) -> Option<PartialMergeResult<E>> {
        let mut assemblies = self.assemblies.write();
        let assembly = assemblies
            .entry(block_root)
            .or_insert_with(|| PartialAssembly {
                header: header.clone(),
                has_local_blobs: false,
                columns: HashMap::new(),
            });

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
                let merged = match existing.merge(&partial) {
                    Ok(merged) => merged,
                    Err(err) => {
                        error!(error = ?err, "Unexpected error merging partial data column");
                        continue;
                    }
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
            let column = if let Some(full_column) = merged.try_clone_full(&header) {
                full_columns.push(full_column.clone());
                AssemblyColumn::Complete(full_column)
            } else {
                AssemblyColumn::Incomplete(merged.clone())
            };

            // Update assembly with merged partial
            assembly.columns.insert(column_index, column);
            updated_partials.push(merged);
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
    pub fn mark_as_complete(
        &self,
        block_root: Hash256,
        column: &KzgVerifiedCustodyDataColumn<E>,
    ) -> bool {
        // TODO(gloas): support partial messages
        let Ok(fulu) = column.as_data_column().as_fulu() else {
            return false;
        };

        let mut assemblies = self.assemblies.write();
        let assembly = assemblies
            .entry(block_root)
            .or_insert_with(|| PartialAssembly {
                header: Arc::new(PartialDataColumnHeader {
                    kzg_commitments: fulu.kzg_commitments.clone(),
                    signed_block_header: fulu.signed_block_header.clone(),
                    kzg_commitments_inclusion_proof: fulu.kzg_commitments_inclusion_proof.clone(),
                }),
                has_local_blobs: false,
                columns: Default::default(),
            });
        let prev = assembly
            .columns
            .insert(column.index(), AssemblyColumn::Complete(column.clone()));
        !matches!(prev, Some(AssemblyColumn::Complete(_)))
    }

    /// Returns true if the given column is complete.
    pub fn is_complete(&self, block_root: Hash256, column_index: ColumnIndex) -> bool {
        self.assemblies.read().peek(&block_root).is_some_and(|a| {
            matches!(
                a.columns.get(&column_index),
                Some(AssemblyColumn::Complete(_))
            )
        })
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

    /// Get all current columns for a block (complete *and* incomplete) for publishing after
    /// fetching local blobs.
    ///
    /// To unlock future publishing, mark blobs as fetched locally. We do this within one write
    /// lock to avoid useless double publishes.
    pub fn get_columns_and_mark_as_local_fetched(
        &self,
        block_root: Hash256,
        header: &Arc<PartialDataColumnHeader<E>>,
    ) -> Vec<AssemblyColumn<E>> {
        let mut assemblies = self.assemblies.write();
        let assembly = assemblies
            .entry(block_root)
            .or_insert_with(|| PartialAssembly {
                header: header.clone(),
                has_local_blobs: true,
                columns: Default::default(),
            });

        assembly.has_local_blobs = true;

        assembly.columns.values().cloned().collect()
    }

    /// Get header for a block if we have an active assembly
    pub fn get_header(&self, block_root: &Hash256) -> Option<Arc<PartialDataColumnHeader<E>>> {
        self.assemblies
            .read()
            .peek(block_root)
            .map(|a| a.header.clone())
    }

    /// Maintenance: remove assemblies older than cutoff epoch
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) {
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
            assemblies.remove(&root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_column_verification::{
        KzgVerifiedCustodyPartialDataColumn, KzgVerifiedDataColumn, KzgVerifiedPartialDataColumn,
    };
    use bls::{FixedBytesExtended, Signature};
    use kzg::{KzgCommitment, KzgProof};
    use ssz_types::{FixedVector, VariableList};
    use types::block::{BeaconBlockHeader, SignedBeaconBlockHeader};
    use types::core::{EthSpec, Hash256, MinimalEthSpec, Slot};
    use types::data::{
        Cell, CellBitmap, DataColumnSidecar, DataColumnSidecarFulu, PartialDataColumn,
        PartialDataColumnSidecar,
    };

    type E = MinimalEthSpec;

    fn make_cell(marker: u8) -> Cell<E> {
        let mut cell = Cell::<E>::default();
        cell[0] = marker;
        cell
    }

    fn make_header(num_commitments: usize) -> PartialDataColumnHeader<E> {
        PartialDataColumnHeader {
            kzg_commitments: vec![KzgCommitment([0u8; 48]); num_commitments]
                .try_into()
                .unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot: Slot::new(1),
                    proposer_index: 0,
                    parent_root: Hash256::zero(),
                    state_root: Hash256::zero(),
                    body_root: Hash256::zero(),
                },
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: FixedVector::new(
                vec![Hash256::zero(); E::kzg_commitments_inclusion_proof_depth()],
            )
            .unwrap(),
        }
    }

    fn make_partial(
        block_root: Hash256,
        column_index: ColumnIndex,
        total_blobs: usize,
        present_indices: &[usize],
    ) -> KzgVerifiedCustodyPartialDataColumn<E> {
        make_partial_with_header(block_root, column_index, total_blobs, present_indices, true)
    }

    fn make_partial_with_header(
        block_root: Hash256,
        column_index: ColumnIndex,
        total_blobs: usize,
        present_indices: &[usize],
        include_header: bool,
    ) -> KzgVerifiedCustodyPartialDataColumn<E> {
        let mut bitmap = CellBitmap::<E>::with_capacity(total_blobs).unwrap();
        for &idx in present_indices {
            bitmap.set(idx, true).unwrap();
        }

        let column: VariableList<_, _> = present_indices
            .iter()
            .map(|&idx| make_cell(idx as u8))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let proofs: VariableList<_, _> = present_indices
            .iter()
            .map(|_| KzgProof::empty())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let header = include_header.then(|| make_header(total_blobs)).into();

        let partial = PartialDataColumn {
            block_root,
            index: column_index,
            sidecar: PartialDataColumnSidecar {
                cells_present_bitmap: bitmap,
                column,
                kzg_proofs: proofs,
                header,
            },
        };
        KzgVerifiedCustodyPartialDataColumn::from_asserted_custody(
            KzgVerifiedPartialDataColumn::__new_for_testing(Arc::new(partial)),
        )
    }

    fn make_full_column(fulu: DataColumnSidecarFulu<E>) -> KzgVerifiedCustodyDataColumn<E> {
        KzgVerifiedCustodyDataColumn::from_asserted_custody(
            KzgVerifiedDataColumn::__new_for_testing(Arc::new(DataColumnSidecar::Fulu(fulu))),
        )
    }

    fn make_assembler() -> PartialDataColumnAssembler<E> {
        PartialDataColumnAssembler::new(16)
    }

    // -- init and get_header tests --

    #[test]
    fn init_stores_header() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = make_header(4);
        assert!(assembler.init(root, Arc::new(header.clone())));
        let retrieved = assembler.get_header(&root).unwrap();
        assert_eq!(*retrieved, header);
    }

    #[test]
    fn init_returns_false_if_already_exists() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = Arc::new(make_header(4));
        assert!(assembler.init(root, header.clone()));
        assert!(!assembler.init(root, header));
    }

    // -- merge_partials tests --

    #[test]
    fn merge_partials_tracks_added_cells() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = Arc::new(make_header(4));

        let partial = make_partial(root, 0, 4, &[0, 1, 2]);
        let result = assembler
            .merge_partials(root, vec![partial], header.clone())
            .unwrap();
        assert_eq!(result.added_cells, 3);

        // Merge more cells for the same column
        let partial2 = make_partial(root, 0, 4, &[2, 3]);
        let result2 = assembler
            .merge_partials(root, vec![partial2], header)
            .unwrap();
        // Only cell 3 is new (cell 2 was already present)
        assert_eq!(result2.added_cells, 1);
    }

    #[test]
    fn merge_partials_ignores_already_complete_column() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = Arc::new(make_header(4));

        // Complete the column
        let partial = make_partial(root, 0, 4, &[0, 1, 2, 3]);
        let result = assembler
            .merge_partials(root, vec![partial], header.clone())
            .unwrap();
        assert_eq!(result.added_cells, 4);
        assert_eq!(result.full_columns.len(), 1);

        // Try to merge more — should be ignored
        let partial2 = make_partial(root, 0, 4, &[0, 1]);
        let result2 = assembler
            .merge_partials(root, vec![partial2], header)
            .unwrap();
        assert_eq!(result2.added_cells, 0);
        assert!(result2.full_columns.is_empty());
    }

    #[test]
    fn merge_partials_completes_column_progressively() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = Arc::new(make_header(4));

        let partial1 = make_partial(root, 0, 4, &[0, 1]);
        let result1 = assembler
            .merge_partials(root, vec![partial1], header.clone())
            .unwrap();
        assert!(result1.full_columns.is_empty());

        let partial2 = make_partial(root, 0, 4, &[2, 3]);
        let result2 = assembler
            .merge_partials(root, vec![partial2], header)
            .unwrap();
        assert_eq!(result2.full_columns.len(), 1);
    }

    #[test]
    fn merge_partials_returns_updated_partials() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = Arc::new(make_header(4));

        let partial = make_partial(root, 0, 4, &[0, 2]);
        let result = assembler
            .merge_partials(root, vec![partial], header)
            .unwrap();
        assert_eq!(result.updated_partials.len(), 1);
        assert_eq!(result.updated_partials[0].index(), 0);
    }

    #[test]
    fn get_columns_returns_complete_and_incomplete() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = Arc::new(make_header(4));

        // One complete column (all cells present) and one still-incomplete column.
        let complete = make_partial(root, 0, 4, &[0, 1, 2, 3]);
        let incomplete = make_partial(root, 1, 4, &[0, 1]);
        assembler.merge_partials(root, vec![complete, incomplete], header.clone());

        // Both must be returned for seeding. Previously the complete column was dropped, so it was
        // published as an empty placeholder and never served to peers.
        let columns = assembler.get_columns_and_mark_as_local_fetched(root, &header);
        assert_eq!(columns.len(), 2);
        assert_eq!(
            columns
                .iter()
                .filter(|c| matches!(c, AssemblyColumn::Complete(_)))
                .count(),
            1
        );
        assert_eq!(
            columns
                .iter()
                .filter(|c| matches!(c, AssemblyColumn::Incomplete(_)))
                .count(),
            1
        );
    }

    // -- mark_as_complete tests --

    #[test]
    fn mark_as_complete_replaces_incomplete() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        let header = Arc::new(make_header(4));

        // Merge an incomplete partial first
        let partial = make_partial(root, 0, 4, &[0, 1]);
        assembler.merge_partials(root, vec![partial], header);

        let full_column = make_full_column(DataColumnSidecarFulu::<E> {
            index: 0,
            column: vec![Cell::<E>::default(); 4].try_into().unwrap(),
            kzg_commitments: vec![KzgCommitment([0u8; 48]); 4].try_into().unwrap(),
            kzg_proofs: vec![KzgProof::empty(); 4].try_into().unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot: Slot::new(1),
                    proposer_index: 0,
                    parent_root: Hash256::zero(),
                    state_root: Hash256::zero(),
                    body_root: Hash256::zero(),
                },
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: FixedVector::new(
                vec![Hash256::zero(); E::kzg_commitments_inclusion_proof_depth()],
            )
            .unwrap(),
        });
        assert!(assembler.mark_as_complete(root, &full_column));
    }

    #[test]
    fn mark_as_complete_returns_false_if_already_complete() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);

        let full_column = make_full_column(DataColumnSidecarFulu::<E> {
            index: 0,
            column: vec![Cell::<E>::default(); 4].try_into().unwrap(),
            kzg_commitments: vec![KzgCommitment([0u8; 48]); 4].try_into().unwrap(),
            kzg_proofs: vec![KzgProof::empty(); 4].try_into().unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot: Slot::new(1),
                    proposer_index: 0,
                    parent_root: Hash256::zero(),
                    state_root: Hash256::zero(),
                    body_root: Hash256::zero(),
                },
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: FixedVector::new(
                vec![Hash256::zero(); E::kzg_commitments_inclusion_proof_depth()],
            )
            .unwrap(),
        });
        assert!(assembler.mark_as_complete(root, &full_column));
        assert!(!assembler.mark_as_complete(root, &full_column));
    }

    // -- do_maintenance tests --

    #[test]
    fn do_maintenance_removes_old_assemblies() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        // Header at slot 0 → epoch 0
        let header = Arc::new(make_header(4));
        assembler.init(root, header);
        assert!(assembler.get_header(&root).is_some());

        // Cutoff epoch 1 removes epoch 0
        assembler.do_maintenance(Epoch::new(1));
        assert!(assembler.get_header(&root).is_none());
    }

    #[test]
    fn do_maintenance_keeps_recent_assemblies() {
        let assembler = make_assembler();
        let root = Hash256::repeat_byte(1);
        // Header at slot 100 → epoch 100/8 = 12 for MinimalEthSpec (8 slots/epoch)
        let mut header = make_header(4);
        header.signed_block_header.message.slot = Slot::new(100);
        let header = Arc::new(header);
        assembler.init(root, header);

        assembler.do_maintenance(Epoch::new(1));
        assert!(assembler.get_header(&root).is_some());
    }
}
