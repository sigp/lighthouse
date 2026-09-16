use crate::beacon_chain::BeaconChainTypes;
use crate::custody_context::CustodyContext;
use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_column_verification::{
    KzgVerifiedCustodyDataColumn, KzgVerifiedCustodyPartialDataColumnGloas, KzgVerifiedDataColumn,
};
use crate::partial_data_column_assembler::{PartialMergeResult, UpdatedPartials};
use crate::payload_envelope_verification::AvailabilityPendingExecutedEnvelope;
use crate::payload_envelope_verification::AvailableEnvelope;
use crate::payload_envelope_verification::AvailableExecutedEnvelope;
use crate::pending_payload_cache::pending_column::PendingColumn;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::DataColumnSidecar;
use types::execution::{ProofType, SignedExecutionProofEnvelope};
use types::{ColumnIndex, EthSpec, Hash256, SignedExecutionPayloadBid};

/// This represents the components of a payload pending data availability.
///
/// The columns are all gossip and kzg verified.
/// The payload is considered "available" when all required columns are received.
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub bid: Arc<SignedExecutionPayloadBid<E>>,
    /// a cached post executed payload envelope
    pub envelope: Option<AvailabilityPendingExecutedEnvelope<E>>,
    /// A column entry in this map may only have some cells filled in (i.e. a partial data column)
    pub verified_data_columns: HashMap<ColumnIndex, PendingColumn<E>>,
    /// Execution proofs keyed by proof type, so repeats from one prover count once. Empty
    /// without a proof engine.
    pub execution_proofs: HashMap<ProofType, Arc<SignedExecutionProofEnvelope>>,
    pub reconstruction_started: bool,
    /// True once the local `getBlobs` attempt has settled. It is set whether or not the EL
    /// returned anything. Until then, republished partials request no cells, because the EL
    /// may supply them for free.
    pub local_fetch_settled: bool,
    pub(crate) span: Span,
}

impl<E: EthSpec> PendingComponents<E> {
    pub fn num_columns_required<T>(&self, custody_context: &CustodyContext<T>) -> usize
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        if custody_context.data_columns_required_for_bid(&self.bid) {
            custody_context.num_of_data_columns_to_sample(self.bid.epoch())
        } else {
            0
        }
    }

    /// Returns columns that have all cells present.
    pub fn get_cached_data_columns(&self) -> Vec<Arc<DataColumnSidecar<E>>> {
        let slot = self.bid.message.slot;
        let block_root = self.block_root;
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| col.to_full_sidecar(*col_idx, slot, block_root))
            .collect()
    }

    /// Returns the indices of columns that have all cells present.
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        let slot = self.bid.message.slot;
        let block_root = self.block_root;
        self.verified_data_columns
            .iter()
            .filter_map(|(col_idx, col)| {
                col.to_full_sidecar(*col_idx, slot, block_root)
                    .map(|_| *col_idx)
            })
            .collect()
    }

    /// Returns all partial (complete and incomplete) columns currently in the cache, suitable for
    /// re-publishing.
    pub(crate) fn get_cached_partial_data_columns(
        &self,
    ) -> Vec<KzgVerifiedCustodyPartialDataColumnGloas<E>> {
        let block_root = self.block_root;
        let slot = self.bid.message.slot;
        self.verified_data_columns
            .iter()
            .filter_map(|(idx, col)| {
                let partial = col.to_partial(*idx, slot, block_root)?;
                Some(KzgVerifiedCustodyPartialDataColumnGloas::from_cached(
                    Arc::new(partial),
                ))
            })
            .collect()
    }

    /// Merges a given set of data columns into the cache.
    pub(crate) fn merge_data_columns(
        &mut self,
        kzg_verified_data_columns: &[KzgVerifiedCustodyDataColumn<E>],
    ) {
        let num_blobs_expected = self.bid.num_blobs_expected();
        for data_column in kzg_verified_data_columns {
            let data_column = data_column.as_data_column();
            // The Vec-backed `PendingColumn` keys cells by index, so we have to allocate up to
            // `num_blobs_expected` entries before inserting; otherwise `cells.get_mut(idx)` returns
            // None and the insert is a no-op.
            let col = self
                .verified_data_columns
                .entry(*data_column.index())
                .or_insert_with(|| PendingColumn::new_with_capacity(num_blobs_expected));
            for (cell_idx, (cell, proof)) in data_column
                .column()
                .iter()
                .zip(data_column.kzg_proofs().iter())
                .enumerate()
            {
                col.insert(cell_idx, cell, proof);
            }
        }
    }

    /// Merges a given set of partial data columns into the cache.
    pub(crate) fn merge_partial_data_columns(
        &mut self,
        kzg_verified_partial_data_columns: &[KzgVerifiedCustodyPartialDataColumnGloas<E>],
    ) -> PartialColumnsMergeOutcome {
        let mut outcome = PartialColumnsMergeOutcome::default();
        for partial in kzg_verified_partial_data_columns {
            let col_index = partial.index();
            let sidecar = partial.sidecar();

            let col = self
                .verified_data_columns
                .entry(col_index)
                .or_insert_with(|| PendingColumn::new_with_capacity(self.bid.num_blobs_expected()));

            if col.is_complete() {
                // Nothing to do.
                continue;
            }

            let mut inserted_cells = 0;
            for (blob_idx, cell, proof) in sidecar.present_cells() {
                if col.insert(blob_idx, cell, proof) {
                    inserted_cells += 1;
                }
            }

            if inserted_cells > 0 {
                outcome.added_cells += inserted_cells;
                outcome.updated.push(col_index);
            }

            if col.is_complete() {
                outcome.newly_complete.push(col_index);
            }
        }
        outcome
    }

    /// Builds the publish list named by a merge outcome.
    ///
    /// This is separate from `merge_partial_data_columns` because it clones every cell. The merge
    /// runs under the write lock. This runs after the downgrade, under a read guard.
    pub(crate) fn to_partial_merge_result(
        &self,
        outcome: PartialColumnsMergeOutcome,
        disable_get_blobs: bool,
    ) -> PartialMergeResult<E> {
        let slot = self.bid.message.slot;

        let full_columns = outcome
            .newly_complete
            .into_iter()
            .filter_map(|col_idx| {
                let data = self.verified_data_columns.get(&col_idx)?.to_full_sidecar(
                    col_idx,
                    slot,
                    self.block_root,
                )?;
                Some(KzgVerifiedCustodyDataColumn::from_asserted_custody(
                    KzgVerifiedDataColumn::from_execution_verified(data),
                ))
            })
            .collect();

        let updated_partials = outcome
            .updated
            .into_iter()
            .filter_map(|col_idx| {
                self.verified_data_columns
                    .get(&col_idx)?
                    .to_partial(col_idx, slot, self.block_root)
            })
            .collect();

        PartialMergeResult {
            added_cells: outcome.added_cells,
            local_fetch_settled: self.local_fetch_settled || disable_get_blobs,
            full_columns,
            updated_partials: UpdatedPartials::Gloas(updated_partials),
        }
    }

    /// Inserts an execution proof, returning the distinct proof type count, or `None` if we
    /// already had this type.
    pub fn insert_execution_proof(
        &mut self,
        proof: Arc<SignedExecutionProofEnvelope>,
    ) -> Option<usize> {
        if self
            .execution_proofs
            .insert(proof.proof_type(), proof)
            .is_some()
        {
            return None;
        }
        Some(self.execution_proofs.len())
    }

    /// Inserts an executed payload envelope into the cache.
    pub fn insert_executed_payload_envelope(
        &mut self,
        envelope: AvailabilityPendingExecutedEnvelope<E>,
    ) {
        self.envelope = Some(envelope);
    }

    pub fn num_completed_columns(&self) -> usize {
        self.get_cached_data_columns().len()
    }

    /// Returns whether our custody requirement for this block's data columns has been
    /// fulfilled, independent of whether the payload envelope itself has been received.
    pub fn is_blob_data_available(&self, num_expected_columns: usize) -> bool {
        self.num_completed_columns() >= num_expected_columns
    }

    /// Returns `Some` once the envelope, the required columns and enough proofs have arrived.
    pub fn make_available<T>(
        &self,
        custody_context: &CustodyContext<T>,
        required_execution_proofs: usize,
    ) -> Result<Option<AvailableExecutedEnvelope<E>>, AvailabilityCheckError>
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        // Check if the payload has been received and executed
        let Some(envelope) = &self.envelope else {
            return Ok(None);
        };

        // Proofs are recursive, so we only need them for this payload, not its ancestors.
        if self.execution_proofs.len() < required_execution_proofs {
            return Ok(None);
        }

        let AvailabilityPendingExecutedEnvelope {
            envelope,
            block_root,
            payload_verification_outcome,
        } = envelope;

        let num_columns_required = self.num_columns_required(custody_context);
        let columns = if num_columns_required == 0 {
            if self.bid.num_blobs_expected() == 0 {
                self.span.in_scope(|| {
                    debug!("Bid has no blobs, data is available");
                });
            } else {
                self.span.in_scope(|| {
                    debug!("No data columns required for this epoch");
                });
            }
            vec![]
        } else {
            let columns = self.get_cached_data_columns();
            match columns.len().cmp(&num_columns_required) {
                Ordering::Greater => {
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many columns: got {} expected {num_columns_required}",
                        columns.len()
                    )));
                }
                Ordering::Equal => {
                    self.span.in_scope(|| {
                        debug!("All data columns received, data is available");
                    });
                    columns
                }
                Ordering::Less => {
                    // Not enough data columns received yet
                    return Ok(None);
                }
            }
        };

        let available_envelope =
            AvailableEnvelope::new(envelope.clone(), columns, &self.bid, custody_context)?;

        Ok(Some(AvailableExecutedEnvelope {
            envelope: available_envelope,
            block_root: *block_root,
            payload_verification_outcome: payload_verification_outcome.clone(),
        }))
    }

    /// Constructs a fresh `PendingComponents` with no envelope and no columns yet.
    pub fn new(block_root: Hash256, bid: Arc<SignedExecutionPayloadBid<E>>) -> Self {
        let span = debug_span!(parent: None, "lh_pending_components", %block_root);
        let _guard = span.clone().entered();
        Self {
            block_root,
            bid,
            envelope: None,
            verified_data_columns: HashMap::new(),
            execution_proofs: HashMap::new(),
            reconstruction_started: false,
            local_fetch_settled: false,
            span,
        }
    }

    pub fn status_str<T>(
        &self,
        custody_context: &CustodyContext<T>,
        required_execution_proofs: usize,
    ) -> String
    where
        T: BeaconChainTypes<EthSpec = E>,
    {
        let num_columns_required = self.num_columns_required(custody_context);
        if required_execution_proofs == 0 {
            format!(
                "envelope {}, data_columns {}/{}",
                self.envelope.is_some(),
                self.num_completed_columns(),
                num_columns_required
            )
        } else {
            format!(
                "envelope {}, data_columns {}/{}, execution_proofs {}",
                self.envelope.is_some(),
                self.num_completed_columns(),
                num_columns_required,
                self.execution_proofs.len()
            )
        }
    }
}

/// Outcome of merging partial data columns into the cache.
#[derive(Default)]
pub(crate) struct PartialColumnsMergeOutcome {
    /// Number of cells newly inserted by the merge (cells already present don't count).
    pub added_cells: usize,
    /// Indices of columns that gained at least one new cell.
    pub updated: Vec<ColumnIndex>,
    /// Indices of columns that became fully populated as a result of the merge.
    pub newly_complete: Vec<ColumnIndex>,
}

// This enum is only used internally within the crate in the reconstruction function to improve
// readability, so it's OK to not box the variant value, and it shouldn't impact memory much with
// the current usage, as it's deconstructed immediately.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReconstructColumnsDecision<E: EthSpec> {
    Yes(Vec<Arc<DataColumnSidecar<E>>>),
    No(&'static str),
}
