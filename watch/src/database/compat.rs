//! Implementations of PostgreSQL compatibility traits.
use crate::database::watch_types::{WatchHash, WatchPK, WatchSlot};
use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::{Binary, Integer};

use std::convert::TryFrom;

macro_rules! impl_to_from_sql_int {
    ($type:ty) => {
        impl ToSql<Integer, Pg> for $type
        where
            i32: ToSql<Integer, Pg>,
        {
            fn to_sql<'a>(&'a self, out: &mut Output<'a, '_, Pg>) -> serialize::Result {
                let v = i32::try_from(self.as_u64()).map_err(|e| Box::new(e))?;
                <i32 as ToSql<Integer, Pg>>::to_sql(&v, &mut out.reborrow())
            }
        }

        impl FromSql<Integer, Pg> for $type {
            fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
                Ok(Self::new(i32::from_sql(bytes)? as u64))
            }
        }
    };
}

macro_rules! impl_to_from_sql_binary {
    ($type:ty) => {
        impl ToSql<Binary, Pg> for $type {
            fn to_sql<'a>(&'a self, out: &mut Output<'a, '_, Pg>) -> serialize::Result {
                let b = self.as_bytes();
                <&[u8] as ToSql<Binary, Pg>>::to_sql(&b, &mut out.reborrow())
            }
        }

        impl FromSql<Binary, Pg> for $type {
            fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
                Self::from_bytes(bytes.as_bytes()).map_err(|e| e.to_string().into())
            }
        }
    };
}

impl_to_from_sql_int!(WatchSlot);
impl_to_from_sql_binary!(WatchHash);
impl_to_from_sql_binary!(WatchPK);
