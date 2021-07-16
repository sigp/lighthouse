pub mod attestation_subnets;
pub mod sync_subnets;

use eth2_libp2p::{Subnet, SubnetDiscovery};

pub use attestation_subnets::AttestationService;
pub use sync_subnets::SyncCommitteeService;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub enum SubnetServiceMessage {
    /// Subscribe to the specified subnet id.
    Subscribe(Subnet),
    /// Unsubscribe to the specified subnet id.
    Unsubscribe(Subnet),
    /// Add the `SubnetId` to the ENR bitfield.
    EnrAdd(Subnet),
    /// Remove the `SubnetId` from the ENR bitfield.
    EnrRemove(Subnet),
    /// Discover peers for a list of `SubnetDiscovery`.
    DiscoverPeers(Vec<SubnetDiscovery>),
}

/// Note: This `PartialEq` impl is for use only in tests.
/// The `DiscoverPeers` comparison is good enough for testing only.
#[cfg(test)]
impl PartialEq for SubnetServiceMessage {
    fn eq(&self, other: &SubnetServiceMessage) -> bool {
        match (self, other) {
            (SubnetServiceMessage::Subscribe(a), SubnetServiceMessage::Subscribe(b)) => a == b,
            (SubnetServiceMessage::Unsubscribe(a), SubnetServiceMessage::Unsubscribe(b)) => a == b,
            (SubnetServiceMessage::EnrAdd(a), SubnetServiceMessage::EnrAdd(b)) => a == b,
            (SubnetServiceMessage::EnrRemove(a), SubnetServiceMessage::EnrRemove(b)) => a == b,
            (SubnetServiceMessage::DiscoverPeers(a), SubnetServiceMessage::DiscoverPeers(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                for i in 0..a.len() {
                    if a[i].subnet != b[i].subnet || a[i].min_ttl != b[i].min_ttl {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }
}
