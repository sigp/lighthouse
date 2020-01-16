//! Identifies each shard by an integer identifier.
use std::ops::{Deref, DerefMut};

pub struct SubnetId(u64);

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
