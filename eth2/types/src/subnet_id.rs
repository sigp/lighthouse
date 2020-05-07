//! Identifies each shard by an integer identifier.
use serde_derive::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubnetId(u64);

impl SubnetId {
    pub fn new(id: u64) -> Self {
        SubnetId(id)
    }
}

impl Deref for SubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
