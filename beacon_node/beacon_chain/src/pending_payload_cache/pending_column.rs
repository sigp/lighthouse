use kzg::KzgProof;
use ssz_types::VariableList;
use std::sync::Arc;
use types::{Cell, ColumnIndex, DataColumnSidecar, DataColumnSidecarGloas, EthSpec, Hash256, Slot};

#[derive(Clone)]
pub struct PendingColumn<E: EthSpec> {
    cells: Vec<Option<(Cell<E>, KzgProof)>>,
}

impl<E: EthSpec> Default for PendingColumn<E> {
    fn default() -> Self {
        Self { cells: Vec::new() }
    }
}

impl<E: EthSpec> PendingColumn<E> {
    pub fn new_with_capacity(_blobs: usize) -> Self {
        Self { cells: Vec::new() }
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

    pub fn is_complete(&self, blob_count: usize) -> bool {
        self.cells.len() == blob_count && self.cells.iter().all(|cell| cell.is_some())
    }

    pub fn try_to_sidecar(
        &self,
        index: ColumnIndex,
        slot: Slot,
        beacon_block_root: Hash256,
        blob_count: usize,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        if self.cells.len() != blob_count {
            return None;
        }

        let mut column = Vec::with_capacity(blob_count);
        let mut kzg_proofs = Vec::with_capacity(self.cells.len());

        for cell in self.cells.iter() {
            let Some((cell, proof)) = cell else {
                return None;
            };
            // TODO(gloas): we likely want to go and arc all cells
            column.push(cell.clone());
            kzg_proofs.push(*proof);
        }

        Some(Arc::new(DataColumnSidecar::Gloas(DataColumnSidecarGloas {
            index,
            // TODO(gloas): this should not error, but we need to catch it
            column: VariableList::try_from(column).ok()?,
            kzg_proofs: VariableList::try_from(kzg_proofs).ok()?,
            slot,
            beacon_block_root,
        })))
    }
}
