use crate::{BeaconChain, BeaconChainTypes};
use store::{Error as StoreError, KeyValueStore};
use types::{DataColumnSidecarList, Hash256};

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
    /// Return the number of `data_columns` successfully imported.
    pub fn import_historical_data_column_batch(
        &self,
        historical_data_column_sidecar_list: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<usize, HistoricalDataColumnError> {
        let mut total_imported = 0;
        let expected_imported = historical_data_column_sidecar_list.len();
        let mut ops = vec![];

        if historical_data_column_sidecar_list.is_empty() {
            return Ok(total_imported);
        }

        for data_column_sidecar in historical_data_column_sidecar_list {
            let block_root = data_column_sidecar.block_root();

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

        tracing::debug!(total_imported, "Imported historical data columns");

        Ok(total_imported)
    }
}
