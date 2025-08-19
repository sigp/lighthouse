use std::collections::{HashMap, HashSet};

use crate::{BeaconChain, BeaconChainTypes};
use store::{Error as StoreError, KeyValueStore};
use types::{ColumnIndex, DataColumnSidecarList, Epoch, EthSpec, Hash256, Slot};

#[derive(Debug)]
pub enum HistoricalDataColumnError {
    /// The provided data column sidecar contains a block signature that doesn't match
    /// the block stored in the database.
    InvalidSignature {
        data_column_block_root: Hash256,
    },

    // The provided data column sidecar pertains to a block that doesn't exist in the database.
    NoBlockFound {
        data_column_block_root: Hash256,
    },

    /// Logic error: should never occur.
    IndexOutOfBounds,

    /// The provided data column sidecar lists doesn't contain columns for the full range of slots for the given epoch.
    MissingDataColumns {
        missing_slots_and_data_columns: HashMap<Slot, HashSet<ColumnIndex>>,
    },

    /// Internal store error
    StoreError(StoreError),
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
    /// block stored in the DB. This function assumes that KZG proofs have already been verified.
    ///
    /// This function requires that the data column sidecar list contains columns for a full epoch.
    ///
    /// Return the number of `data_columns` successfully imported.
    pub fn import_historical_data_column_batch(
        &self,
        epoch: Epoch,
        historical_data_column_sidecar_list: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<usize, HistoricalDataColumnError> {
        tracing::info!(?epoch, "Uploading historical data column batch to the store");
        let mut total_imported = 0;
        let expected_imported = historical_data_column_sidecar_list.len();
        let mut ops = vec![];

        let unique_column_indices = historical_data_column_sidecar_list
            .iter()
            .map(|item| item.index)
            .collect::<HashSet<_>>();

        let slots_to_update = epoch
            .slot_iter(T::EthSpec::slots_per_epoch())
            .collect::<HashSet<_>>();

        let mut columns_to_update_per_slot: HashMap<Slot, HashSet<u64>> = slots_to_update
            .iter()
            .map(|&slot| (slot, unique_column_indices.clone()))
            .collect();

        if historical_data_column_sidecar_list.is_empty() {
            return Ok(total_imported);
        }

        for data_column_sidecar in historical_data_column_sidecar_list {
            let block_root = data_column_sidecar.block_root();
            let slot = data_column_sidecar.slot();

            if let Some(indices) = columns_to_update_per_slot.get_mut(&slot) {
                indices.remove(&data_column_sidecar.index);
                if indices.is_empty() {
                    columns_to_update_per_slot.remove(&slot);
                }
            }

            let Some(block) = self.store.get_blinded_block(&block_root)? else {
                let error = HistoricalDataColumnError::NoBlockFound {
                    data_column_block_root: block_root,
                };
                tracing::warn!(
                    %block_root,
                    num_blob_sidecars = expected_imported,
                    ?error,
                    "Aborting data column sidecar import"
                );
                return Err(error);
            };

            if &data_column_sidecar.signed_block_header.signature != block.signature() {
                let error = HistoricalDataColumnError::InvalidSignature {
                    data_column_block_root: block_root,
                };
                tracing::warn!(
                    block_root = ?block_root,
                    column_index = data_column_sidecar.index,
                    ?error,
                    "Aborting data column sidecar import"
                );
                return Err(error);
            }

            if self
                .store
                .get_data_column(&block_root, &data_column_sidecar.index)?
                .is_none()
            {
                tracing::debug!(
                    block_root = ?block_root,
                    column_index = data_column_sidecar.index,
                    "Skipping data column import as identical data column exists"
                );
                continue;
            }
            self.store
                .data_column_as_kv_store_ops(&block_root, data_column_sidecar, &mut ops);
            total_imported += 1;
        }

        self.store.blobs_db.do_atomically(ops)?;

        if columns_to_update_per_slot.is_empty() {
            self.store.put_data_column_custody_info(Some(
                epoch.start_slot(T::EthSpec::slots_per_epoch()),
            ))?;
        } else {
            tracing::warn!(
                ?epoch,
                missing_slots = ?columns_to_update_per_slot.keys(),
                "Some data columns are missing from the batch"
            );
            return Err(HistoricalDataColumnError::MissingDataColumns {
                missing_slots_and_data_columns: columns_to_update_per_slot,
            });
        }

        tracing::debug!(total_imported, "Imported historical data columns");

        Ok(total_imported)
    }
}
