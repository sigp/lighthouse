use crate::beacon_chain::BeaconChainTypes;
use ssz::{Decode, Encode};
use store::hot_cold_store::HotColdDB;
use store::{DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};
use types::{Hash256, SignedExecutionPayloadEnvelope};

/// Upgrade from schema v30 to v31.
///
/// Splits each signed execution payload envelope in `PayloadEnvelope` into its persistent summary
/// and prunable execution payload.
pub fn upgrade_to_v31<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let mut ops = vec![];

    for result in db.hot_db.iter_column::<Hash256>(DBColumn::PayloadEnvelope) {
        let (block_root, envelope_bytes) = result?;
        let envelope = SignedExecutionPayloadEnvelope::<T::EthSpec>::from_ssz_bytes(
            &envelope_bytes,
        )
        .map_err(|error| {
            StoreError::MigrationError(format!(
                "cannot upgrade from v30 to v31: invalid payload envelope at {block_root:?}: \
                 {error:?}"
            ))
        })?;
        let (summary, payload) = envelope.into();

        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::PayloadEnvelope,
            block_root.as_slice().to_vec(),
            payload.as_ssz_bytes(),
        ));
        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::PayloadSummary,
            block_root.as_slice().to_vec(),
            summary.as_ssz_bytes(),
        ));
    }

    Ok(ops)
}

/// Downgrade from schema v31 to v30.
///
/// This downgrade is only possible prior to Gloas, when there are no payload envelope summaries.
pub fn downgrade_from_v31<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    if let Some(result) = db
        .hot_db
        .iter_column_keys::<Hash256>(DBColumn::PayloadSummary)
        .next()
    {
        let block_root = result?;
        return Err(StoreError::MigrationError(format!(
            "cannot downgrade from v31 to v30 after Gloas: found payload envelope summary for \
             block {block_root:?}"
        )));
    }

    Ok(vec![])
}
