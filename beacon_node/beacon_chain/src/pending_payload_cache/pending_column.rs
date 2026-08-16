use kzg::KzgProof;
use ssz_types::ProgressiveVariableList;
use std::sync::Arc;
use types::data::{CellBitmap, PartialDataColumnGloas, PartialDataColumnSidecarGloas};
use types::{Cell, ColumnIndex, DataColumnSidecar, DataColumnSidecarGloas, EthSpec, Hash256, Slot};

#[derive(Clone)]
pub struct PendingColumn<E: EthSpec> {
    cells: Vec<Option<(Cell<E>, KzgProof)>>,
}

impl<E: EthSpec> PendingColumn<E> {
    /// Allocate a `PendingColumn` whose `cells` vec has space for `blob_count` entries, all
    /// initialised to `None`. Required so that `insert(idx, ...)` can write into `cells[idx]`.
    pub fn new_with_capacity(blob_count: usize) -> Self {
        Self {
            cells: vec![None; blob_count],
        }
    }

    /// Returns `true` if the cell was newly inserted, `false` if it was already present or the
    /// index is out of bounds.
    pub fn insert(&mut self, index: usize, cell: &Cell<E>, proof: &KzgProof) -> bool {
        if let Some(existing_cell) = self.cells.get_mut(index)
            && existing_cell.is_none()
        {
            *existing_cell = Some((cell.clone(), *proof));
            true
        } else {
            false
        }
    }

    /// `None` means this index holds no cell, or the index is out of range. `Some(false)` means a
    /// different cell, which cannot also be valid for the same commitment.
    pub fn cell_matches(&self, index: usize, cell: &Cell<E>, proof: &KzgProof) -> Option<bool> {
        self.cells
            .get(index)?
            .as_ref()
            .map(|(c, p)| c == cell && p == proof)
    }

    /// Returns `true` if all cells of this column are present.
    pub fn is_complete(&self) -> bool {
        self.cells.iter().all(|c| c.is_some())
    }

    /// Build a partial Gloas data column from the cells currently populated. Returns `None` if no
    /// cells are present.
    pub fn to_partial(
        &self,
        index: ColumnIndex,
        slot: Slot,
        block_root: Hash256,
    ) -> Option<PartialDataColumnGloas<E>> {
        let total = self.cells.len();
        let mut bitmap = CellBitmap::<E>::with_capacity(total).ok()?;
        let mut column = Vec::with_capacity(total);
        let mut kzg_proofs = Vec::with_capacity(total);

        for (idx, cell) in self.cells.iter().enumerate() {
            let Some((cell, proof)) = cell.as_ref() else {
                continue;
            };
            bitmap.set(idx, true).ok()?;
            column.push(cell.clone());
            kzg_proofs.push(*proof);
        }

        if column.is_empty() {
            return None;
        }

        Some(PartialDataColumnGloas {
            block_root,
            slot,
            index,
            sidecar: PartialDataColumnSidecarGloas {
                cells_present_bitmap: bitmap,
                column: ProgressiveVariableList::new(column),
                kzg_proofs: ProgressiveVariableList::new(kzg_proofs),
            },
        })
    }

    /// Returns a full `DataColumnSidecar` if all cells are present, or `None` if any are missing.
    pub fn to_full_sidecar(
        &self,
        index: ColumnIndex,
        slot: Slot,
        beacon_block_root: Hash256,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        let mut column = Vec::with_capacity(self.cells.len());
        let mut kzg_proofs = Vec::with_capacity(self.cells.len());

        for cell in self.cells.iter() {
            let (cell, proof) = cell.as_ref()?;
            // TODO(gloas): we likely want to go and arc all cells. This will help us from requiring a clone
            // in PendingColumn::insert
            column.push(cell.clone());
            kzg_proofs.push(*proof);
        }

        // TODO(gloas): this hard-codes the Gloas sidecar variant. Pass the fork in once
        // post-Gloas variants are introduced (or move construction to a fork-aware helper).
        Some(Arc::new(DataColumnSidecar::Gloas(DataColumnSidecarGloas {
            index,
            column: ProgressiveVariableList::from_iter(column),
            kzg_proofs: ProgressiveVariableList::from_iter(kzg_proofs),
            slot,
            beacon_block_root,
        })))
    }
}
