use crate::Error;

/// Transform a transaction that would fail with a `MapFull` error into an optional result.
pub trait TxnMapFull<T, E> {
    fn allow_map_full(self) -> Result<Option<T>, E>;
}

impl<T> TxnMapFull<T, Error> for Result<T, Error> {
    fn allow_map_full(self) -> Result<Option<T>, Error> {
        match self {
            Ok(x) => Ok(Some(x)),
            Err(Error::DatabaseError(mdbx::Error::MapFull)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
