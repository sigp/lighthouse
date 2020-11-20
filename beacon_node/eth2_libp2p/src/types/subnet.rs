use std::time::Instant;
use types::SubnetId;

/// A subnet to discover peers on along with the instant after which it's no longer useful.
#[derive(Debug, Clone)]
pub struct SubnetDiscovery {
    pub subnet_id: SubnetId,
    pub min_ttl: Option<Instant>,
}
