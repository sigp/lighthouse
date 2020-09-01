use std::time::{Duration, Instant};
use types::SubnetId;

const DURATION_DIFFERENCE: Duration = Duration::from_millis(1);

/// A subnet to discover peers on along with the instant after which it's no longer useful.
#[derive(Debug, Clone)]
pub struct SubnetDiscovery {
    pub subnet_id: SubnetId,
    pub min_ttl: Option<Instant>,
}

impl PartialEq for SubnetDiscovery {
    fn eq(&self, other: &SubnetDiscovery) -> bool {
        self.subnet_id == other.subnet_id
            && match (self.min_ttl, other.min_ttl) {
                (Some(min_ttl_instant), Some(other_min_ttl_instant)) => {
                    min_ttl_instant.saturating_duration_since(other_min_ttl_instant)
                        < DURATION_DIFFERENCE
                        && other_min_ttl_instant.saturating_duration_since(min_ttl_instant)
                            < DURATION_DIFFERENCE
                }
                (None, None) => true,
                (None, Some(_)) => true,
                (Some(_), None) => true,
            }
    }
}
