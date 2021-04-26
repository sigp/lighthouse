use serde::{ser::Serializer, Serialize};
use std::time::Instant;
use types::SubnetId;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum Subnet {
    Attestation(SubnetId),
    SyncCommittee(SubnetId),
}

/// A subnet to discover peers on along with the instant after which it's no longer useful.
#[derive(Debug, Clone, Hash)]
pub struct SubnetDiscovery {
    pub subnet_id: Subnet,
    pub min_ttl: Option<Instant>,
}

impl Serialize for SubnetDiscovery {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&self.subnet_id, serializer)
    }
}

impl PartialEq for SubnetDiscovery {
    fn eq(&self, other: &SubnetDiscovery) -> bool {
        self.subnet_id.eq(&other.subnet_id)
    }
}
