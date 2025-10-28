use serde::Serialize;
use std::time::Instant;
use types::{DataColumnSubnetId, SubnetId, SyncSubnetId};

/// Represents a subnet on an attestation or sync committee `SubnetId`.
///
/// Used for subscribing to the appropriate gossipsub subnets and mark
/// appropriate metadata bitfields.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum Subnet {
    /// Represents a gossipsub attestation subnet and the metadata `attnets` field.
    Attestation(SubnetId),
    /// Represents a gossipsub sync committee subnet and the metadata `syncnets` field.
    SyncCommittee(SyncSubnetId),
    /// Represents a gossipsub data column subnet.
    DataColumn(DataColumnSubnetId),
    /// Represents execution proof support. 
    //
    /// Note: ExecutionProof uses a single gossip topic (not multiple topics),
    /// but we track it here for ENR-based peer discovery to find zkVM-enabled peers.
    /// TODO(zkproofs): Is there a way to have peer discovery without adding the global topic
    /// into Subnet?
    ExecutionProof,
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
