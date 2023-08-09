use crate::database::error::Error;
use diesel::{
    sql_types::{Binary, Integer},
    AsExpression, FromSqlRow,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use types::{Epoch, Hash256, PublicKeyBytes, Slot};
#[derive(
    Clone,
    Copy,
    Debug,
    AsExpression,
    FromSqlRow,
    Deserialize,
    Serialize,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[diesel(sql_type = Integer)]
pub struct WatchSlot(Slot);

impl fmt::Display for WatchSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl WatchSlot {
    pub fn new(slot: u64) -> Self {
        Self(Slot::new(slot))
    }

    pub fn from_slot(slot: Slot) -> Self {
        Self(slot)
    }

    pub fn as_slot(self) -> Slot {
        self.0
    }

    pub fn as_u64(self) -> u64 {
        self.0.as_u64()
    }

    pub fn epoch(self, slots_per_epoch: u64) -> Epoch {
        self.as_slot().epoch(slots_per_epoch)
    }
}

#[derive(Clone, Copy, Debug, AsExpression, FromSqlRow, Deserialize, Serialize)]
#[diesel(sql_type = Binary)]
pub struct WatchHash(Hash256);

impl fmt::Display for WatchHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl WatchHash {
    pub fn as_hash(&self) -> Hash256 {
        self.0
    }

    pub fn from_hash(hash: Hash256) -> Self {
        WatchHash(hash)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(src: &[u8]) -> Result<WatchHash, Error> {
        if src.len() == 32 {
            Ok(WatchHash(Hash256::from_slice(src)))
        } else {
            Err(Error::InvalidRoot)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, AsExpression, FromSqlRow, Serialize, Deserialize)]
#[diesel(sql_type = Binary)]
pub struct WatchPK(PublicKeyBytes);

impl fmt::Display for WatchPK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl WatchPK {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_serialized()
    }

    pub fn from_bytes(src: &[u8]) -> Result<WatchPK, Error> {
        Ok(WatchPK(PublicKeyBytes::deserialize(src)?))
    }

    pub fn from_pubkey(key: PublicKeyBytes) -> Self {
        WatchPK(key)
    }
}

impl FromStr for WatchPK {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(WatchPK(
            PublicKeyBytes::from_str(s).map_err(|e| format!("Cannot be parsed: {}", e))?,
        ))
    }
}
