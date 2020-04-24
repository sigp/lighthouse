//! Implementations of SQLite compatibility traits.
use crate::{Epoch, Slot};
use rusqlite::{
    types::{FromSql, FromSqlError, ToSql, ToSqlOutput, ValueRef},
    Error,
};

impl ToSql for Slot {
    fn to_sql(&self) -> Result<ToSqlOutput, Error> {
        Ok(ToSqlOutput::from(self.as_u64() as i64))
    }
}

impl FromSql for Slot {
    fn column_result(value: ValueRef) -> Result<Self, FromSqlError> {
        Ok(Self::new(i64::column_result(value)? as u64))
    }
}

impl ToSql for Epoch {
    fn to_sql(&self) -> Result<ToSqlOutput, Error> {
        Ok(ToSqlOutput::from(self.as_u64() as i64))
    }
}

impl FromSql for Epoch {
    fn column_result(value: ValueRef) -> Result<Self, FromSqlError> {
        Ok(Self::new(i64::column_result(value)? as u64))
    }
}
