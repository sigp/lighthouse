use crate::Error;

/// Mix-in trait for loading values from LMDB that may or may not exist.
pub trait TxnOptional<T, E> {
    fn optional(self) -> Result<Option<T>, E>;
}

impl<T> TxnOptional<T, Error> for Result<T, lmdb::Error> {
    fn optional(self) -> Result<Option<T>, Error> {
        match self {
            Ok(x) => Ok(Some(x)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Transform a transaction that would fail with a `MapFull` error into an optional result.
pub trait TxnMapFull<T, E> {
    fn allow_map_full(self) -> Result<Option<T>, E>;
}

impl<T> TxnMapFull<T, Error> for Result<T, Error> {
    fn allow_map_full(self) -> Result<Option<T>, Error> {
        match self {
            Ok(x) => Ok(Some(x)),
            Err(Error::DatabaseError(lmdb::Error::MapFull)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
