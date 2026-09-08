use crate::beacon_chain::BeaconChainTypes;
use ssz::{Decode, Encode};
use store::hot_cold_store::HotColdDB;
use store::{DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};
use types::{
    ExecutionPayloadGloas, Hash256, SignedExecutionPayloadEnvelope,
    SignedExecutionPayloadEnvelopeSummary,
};

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
/// This downgrade is only possible while every envelope summary still has its execution payload.
/// Once finalized envelope payloads have been pruned, the old full-envelope representation cannot
/// be recovered without asynchronous execution-layer requests during migration.
pub fn downgrade_from_v31<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let mut ops = vec![];

    for result in db.hot_db.iter_column::<Hash256>(DBColumn::PayloadSummary) {
        let (block_root, summary_bytes) = result?;
        let summary =
            SignedExecutionPayloadEnvelopeSummary::<T::EthSpec>::from_ssz_bytes(&summary_bytes)
                .map_err(|error| {
                    StoreError::MigrationError(format!(
                        "cannot downgrade from v31 to v30: invalid payload envelope summary at \
                 {block_root:?}: {error:?}"
                    ))
                })?;
        let payload_bytes = db
            .hot_db
            .get_bytes(DBColumn::PayloadEnvelope, block_root.as_slice())?
            .ok_or_else(|| {
                StoreError::MigrationError(format!(
                    "cannot downgrade from v31 to v30: payload for envelope {block_root:?} has \
                     been pruned"
                ))
            })?;
        let payload = ExecutionPayloadGloas::<T::EthSpec>::from_ssz_bytes(&payload_bytes).map_err(
            |error| {
                StoreError::MigrationError(format!(
                    "cannot downgrade from v31 to v30: invalid envelope payload at \
                     {block_root:?}: {error:?}"
                ))
            },
        )?;

        if payload.block_hash != summary.block_hash() {
            return Err(StoreError::MigrationError(format!(
                "cannot downgrade from v31 to v30: payload hash mismatch for envelope \
                 {block_root:?}"
            )));
        }

        ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::PayloadEnvelope,
            block_root.as_slice().to_vec(),
            summary.into_envelope(payload).as_ssz_bytes(),
        ));
        ops.push(KeyValueStoreOp::DeleteKey(
            DBColumn::PayloadSummary,
            block_root.as_slice().to_vec(),
        ));
    }

    Ok(ops)
}
