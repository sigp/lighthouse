use kzg::KzgProof;
use ssz_types::VariableList;
use std::sync::Arc;
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

    pub fn insert(&mut self, index: usize, cell: &Cell<E>, proof: &KzgProof) {
        if let Some(existing_cell) = self.cells.get_mut(index)
            && existing_cell.is_none()
        {
            *existing_cell = Some((cell.clone(), *proof));
        }
    }

    pub fn cell_matches(&self, index: usize, cell: &Cell<E>, proof: &KzgProof) -> Option<bool> {
        self.cells
            .get(index)?
            .as_ref()
            .map(|(c, p)| c == cell && p == proof)
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
            column: VariableList::try_from(column).ok()?,
            kzg_proofs: VariableList::try_from(kzg_proofs).ok()?,
            slot,
            beacon_block_root,
        })))
    }
}
