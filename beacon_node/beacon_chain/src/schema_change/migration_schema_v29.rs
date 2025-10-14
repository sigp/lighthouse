use store::{DBColumn, Error, KeyValueStoreOp, metadata::DATA_COLUMN_INFO_KEY};

/// Add `DataColumnCustodyInfo` entry to v27.
pub fn upgrade_to_v29() -> Result<Vec<KeyValueStoreOp>, Error> {
    Ok(vec![KeyValueStoreOp::DeleteKey(
        DBColumn::BeaconMeta,
        DATA_COLUMN_INFO_KEY.as_slice().to_vec(),
    )])
}

pub fn downgrade_from_v29() -> Result<(), Error> {
    Err(Error::MigrationError(
        "Cannot downgrade from v29".to_string(),
    ))
}
