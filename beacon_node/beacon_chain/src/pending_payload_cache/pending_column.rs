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

    pub fn is_complete(&self, blob_count: usize) -> bool {
        self.cells.len() == blob_count && self.cells.iter().all(|cell| cell.is_some())
    }

    /// Build a `DataColumnSidecar` from the cached cells.
    ///
    /// Caller MUST have checked `is_complete(blob_count)` first; this returns `Err` only on the
    /// (currently theoretically impossible) `VariableList` size-bound failures, which we surface
    /// as a typed error so the caller can log/metric it instead of silently producing nothing.
    pub fn to_sidecar(
        &self,
        index: ColumnIndex,
        slot: Slot,
        beacon_block_root: Hash256,
    ) -> Result<Arc<DataColumnSidecar<E>>, PendingColumnError> {
        let mut column = Vec::with_capacity(self.cells.len());
        let mut kzg_proofs = Vec::with_capacity(self.cells.len());

        for cell in self.cells.iter() {
            let (cell, proof) = cell.as_ref().ok_or(PendingColumnError::IncompleteColumn)?;
            // TODO(gloas): we likely want to go and arc all cells
            column.push(cell.clone());
            kzg_proofs.push(*proof);
        }

        // TODO(gloas): this hard-codes the Gloas sidecar variant. Pass the fork in once
        // post-Gloas variants are introduced (or move construction to a fork-aware helper).
        Ok(Arc::new(DataColumnSidecar::Gloas(DataColumnSidecarGloas {
            index,
            column: VariableList::try_from(column)
                .map_err(|_| PendingColumnError::ColumnSizeExceedsBound)?,
            kzg_proofs: VariableList::try_from(kzg_proofs)
                .map_err(|_| PendingColumnError::ProofsSizeExceedsBound)?,
            slot,
            beacon_block_root,
        })))
    }
}

/// Errors returned by [`PendingColumn::to_sidecar`]. `IncompleteColumn` should never fire if the
/// caller checks [`PendingColumn::is_complete`] first; the size-bound variants reflect spec-bound
/// invariants and should never fire in practice.
#[derive(Debug, Clone)]
pub enum PendingColumnError {
    IncompleteColumn,
    ColumnSizeExceedsBound,
    ProofsSizeExceedsBound,
}
