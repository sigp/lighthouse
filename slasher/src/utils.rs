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
