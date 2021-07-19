//! Identifies each sync committee subnet by an integer identifier.
use crate::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
use serde_derive::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

lazy_static! {
    static ref SYNC_SUBNET_ID_TO_STRING: Vec<String> = {
        let mut v = Vec::with_capacity(SYNC_COMMITTEE_SUBNET_COUNT as usize);

        for i in 0..SYNC_COMMITTEE_SUBNET_COUNT {
            v.push(i.to_string());
        }
        v
    };
}

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

pub fn sync_subnet_id_to_string(i: u64) -> &'static str {
    if i < SYNC_COMMITTEE_SUBNET_COUNT {
        &SYNC_SUBNET_ID_TO_STRING
            .get(i as usize)
            .expect("index below SYNC_COMMITTEE_SUBNET_COUNT")
    } else {
        "sync subnet id out of range"
    }
}

impl SyncSubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }
}

impl Deref for SyncSubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SyncSubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<u64> for SyncSubnetId {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Into<u64> for SyncSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<u64> for &SyncSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl AsRef<str> for SyncSubnetId {
    fn as_ref(&self) -> &str {
        sync_subnet_id_to_string(self.0)
    }
}
