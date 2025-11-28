use std::collections::{HashMap, HashSet};

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes,
    data_column_verification::verify_kzg_for_data_column_list,
};
use store::{Error as StoreError, KeyValueStore};
use tracing::{Span, debug, instrument};
use types::{ColumnIndex, DataColumnSidecarList, Epoch, EthSpec, Hash256, Slot};

#[derive(Debug)]
pub enum HistoricalDataColumnError {
    // The provided data column sidecar pertains to a block that doesn't exist in the database.
    NoBlockFound {
        data_column_block_root: Hash256,
        expected_block_root: Hash256,
    },

    /// Logic error: should never occur.
    IndexOutOfBounds,

    /// The provided data column sidecar list doesn't contain columns for the full range of slots for the given epoch.
    MissingDataColumns {
        missing_slots_and_data_columns: Vec<(Slot, ColumnIndex)>,
    },

    /// The provided data column sidecar list contains at least one column with an invalid kzg commitment.
    InvalidKzg,

    /// Internal store error
    StoreError(StoreError),

    /// Internal beacon chain error
    BeaconChainError(Box<BeaconChainError>),
}

impl From<StoreError> for HistoricalDataColumnError {
    fn from(e: StoreError) -> Self {
        Self::StoreError(e)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Store a batch of historical data columns in the database.
    ///
    /// The data columns block roots and proposer signatures are verified with the existing
    /// block stored in the DB. This function also verifies the columns KZG committments.
    ///
    /// This function requires that the data column sidecar list contains columns for a full epoch.
    ///
    /// Return the number of `data_columns` successfully imported.
    #[instrument(skip_all, fields(columns_imported_count = tracing::field::Empty ))]
    pub fn import_historical_data_column_batch(
        &self,
        epoch: Epoch,
        historical_data_column_sidecar_list: DataColumnSidecarList<T::EthSpec>,
        expected_cgc: u64,
    ) -> Result<usize, HistoricalDataColumnError> {
        let mut total_imported = 0;
        let mut ops = vec![];

        let unique_column_indices = historical_data_column_sidecar_list
            .iter()
            .map(|item| item.index)
            .collect::<HashSet<_>>();

        let mut slot_and_column_index_to_data_columns = historical_data_column_sidecar_list
            .iter()
            .map(|data_column| ((data_column.slot(), data_column.index), data_column))
            .collect::<HashMap<_, _>>();

        let forward_blocks_iter = self
            .forwards_iter_block_roots_until(
                epoch.start_slot(T::EthSpec::slots_per_epoch()),
                epoch.end_slot(T::EthSpec::slots_per_epoch()),
            )
            .map_err(|e| HistoricalDataColumnError::BeaconChainError(Box::new(e)))?;

        for block_iter_result in forward_blocks_iter {
            let (block_root, slot) = block_iter_result
                .map_err(|e| HistoricalDataColumnError::BeaconChainError(Box::new(e)))?;

            for column_index in unique_column_indices.clone() {
                if let Some(data_column) =
                    slot_and_column_index_to_data_columns.remove(&(slot, column_index))
                {
                    if self
                        .store
                        .get_data_column(&block_root, &data_column.index)?
                        .is_some()
                    {
                        continue;
                    }
                    if block_root != data_column.block_root() {
                        return Err(HistoricalDataColumnError::NoBlockFound {
                            data_column_block_root: data_column.block_root(),
                            expected_block_root: block_root,
                        });
                    }
                    self.store.data_column_as_kv_store_ops(
                        &block_root,
                        data_column.clone(),
                        &mut ops,
                    );
                    total_imported += 1;
                }
            }
        }

        // If we've made it to here with no columns to import, this means there are no blobs for this epoch.
        // `RangeDataColumnBatchRequest` logic should have caught any bad peers withholding columns
        if historical_data_column_sidecar_list.is_empty() {
            if !ops.is_empty() {
                // This shouldn't be a valid case. If there are no columns to import,
                // there should be no generated db operations.
                return Err(HistoricalDataColumnError::IndexOutOfBounds);
            }
        } else {
            verify_kzg_for_data_column_list(historical_data_column_sidecar_list.iter(), &self.kzg)
                .map_err(|_| HistoricalDataColumnError::InvalidKzg)?;

            self.store.blobs_db.do_atomically(ops)?;
        }

        if !slot_and_column_index_to_data_columns.is_empty() {
            debug!(
                ?epoch,
                extra_data = ?slot_and_column_index_to_data_columns.keys().map(|(slot, _)| slot),
                "We've received unexpected extra data columns, these will not be imported"
            );
        }

        self.data_availability_checker
            .custody_context()
            .update_and_backfill_custody_count_at_epoch(epoch, expected_cgc);

        self.safely_backfill_data_column_custody_info(epoch)
            .map_err(|e| HistoricalDataColumnError::BeaconChainError(Box::new(e)))?;

        debug!(?epoch, total_imported, "Imported historical data columns");

        let current_span = Span::current();
        current_span.record("columns_imported_count", total_imported);

        Ok(total_imported)
    }
}
