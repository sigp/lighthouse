use kzg::KzgProof;
use ssz_types::VariableList;
use std::collections::HashMap;
use std::sync::Arc;
use types::{Cell, ColumnIndex, DataColumnSidecar, DataColumnSidecarGloas, EthSpec, Hash256, Slot};

#[derive(Clone, Default)]
pub struct PendingColumn<E: EthSpec> {
    cells: HashMap<usize, (Cell<E>, KzgProof)>,
}

impl<E: EthSpec> PendingColumn<E> {
    pub fn insert(&mut self, index: usize, cell: &Cell<E>, proof: &KzgProof) {
        self.cells
            .entry(index)
            .or_insert_with(|| (cell.clone(), *proof));
    }

    pub fn cell_matches(&self, index: usize, cell: &Cell<E>, proof: &KzgProof) -> Option<bool> {
        let (c, p) = self.cells.get(&index)?;
        Some(c == cell && p == proof)
    }

    pub fn is_complete(&self, blob_count: usize) -> bool {
        (0..blob_count).all(|i| self.cells.contains_key(&i))
    }

    pub fn try_to_sidecar(
        &self,
        index: ColumnIndex,
        slot: Slot,
        beacon_block_root: Hash256,
        blob_count: usize,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        let mut column = Vec::with_capacity(blob_count);
        let mut kzg_proofs = Vec::with_capacity(blob_count);

        for i in 0..blob_count {
            let (cell, proof) = self.cells.get(&i)?;
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
