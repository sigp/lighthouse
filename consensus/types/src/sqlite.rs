//! Implementations of SQLite compatibility traits.
use crate::{Epoch, Slot};
use rusqlite::{
    types::{FromSql, FromSqlError, ToSql, ToSqlOutput, ValueRef},
    Error,
};

macro_rules! impl_to_from_sql {
    ($type:ty) => {
        impl ToSql for $type {
            fn to_sql(&self) -> Result<ToSqlOutput, Error> {
                let val_i64 = i64::try_from(self.as_u64())
                    .map_err(|e| Error::ToSqlConversionFailure(Box::new(e)))?;
                Ok(ToSqlOutput::from(val_i64))
            }
        }

        impl FromSql for $type {
            fn column_result(value: ValueRef) -> Result<Self, FromSqlError> {
                let val_u64 = u64::try_from(i64::column_result(value)?)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?;
                Ok(Self::new(val_u64))
            }
        }
    };
}

impl_to_from_sql!(Slot);
impl_to_from_sql!(Epoch);
