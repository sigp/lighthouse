use serde::Serialize;
use std::time::Instant;
use types::SubnetId;

/// Represents a subnet on an attestation or sync committee `SubnetId`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum Subnet {
    Attestation(SubnetId),
    SyncCommittee(SubnetId),
}

/// A subnet to discover peers on along with the instant after which it's no longer useful.
#[derive(Debug, Clone)]
pub struct SubnetDiscovery {
    pub subnet: Subnet,
    pub min_ttl: Option<Instant>,
}

impl PartialEq for SubnetDiscovery {
    fn eq(&self, other: &SubnetDiscovery) -> bool {
        self.subnet.eq(&other.subnet)
    }
}
