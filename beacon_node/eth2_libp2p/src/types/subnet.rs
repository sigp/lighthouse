use std::time::{Duration, Instant};
use types::SubnetId;

const DURATION_DIFFERENCE: Duration = Duration::from_millis(1);

/// A subnet to discover peers on along with the instant after which it's no longer useful.
#[derive(Debug, Clone)]
pub struct SubnetDiscovery {
    pub subnet_id: SubnetId,
    pub min_ttl: Instant,
}

impl PartialEq for SubnetDiscovery {
    fn eq(&self, other: &SubnetDiscovery) -> bool {
        self.subnet_id == other.subnet_id
            && self.min_ttl.saturating_duration_since(other.min_ttl) < DURATION_DIFFERENCE
            && other.min_ttl.saturating_duration_since(self.min_ttl) < DURATION_DIFFERENCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests `PartialEq` implementation for `SubnetDiscovery`
    #[test]
    fn test_equality() {
        let now = Instant::now();

        let s1 = SubnetDiscovery {
            subnet_id: SubnetId::new(1),
            min_ttl: now,
        };
        let mut s2 = SubnetDiscovery {
            subnet_id: SubnetId::new(1),
            min_ttl: now + Duration::from_nanos(500),
        };

        assert_eq!(s1, s2, "min_ttl within DURATION_DIFFERENCE must be equal");
        assert_eq!(s2, s1, "min_ttl within DURATION_DIFFERENCE must be equal");

        s2.min_ttl += DURATION_DIFFERENCE;

        assert_ne!(
            s1, s2,
            "min_ttl not within DURATION_DIFFERENCE should be unequal"
        );
    }
}
