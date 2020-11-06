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
                (None, Some(_)) => false, // not equal
                (Some(_), None) => false, // not equal
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests `PartialEq` implementation for `SubnetDiscovery`
    #[test]
    fn test_equality() {
        let mut s1 = SubnetDiscovery {
            subnet_id: SubnetId::new(1),
            min_ttl: None,
        };
        let mut s2 = SubnetDiscovery {
            subnet_id: SubnetId::new(2),
            min_ttl: None,
        };

        assert_ne!(s1, s2, "unequal subnet_id should be unequal");

        s2.subnet_id = SubnetId::new(1);

        assert_eq!(s1, s2, "equal subnet_id and min_ttl should be equal");

        let instant = Instant::now();

        s1.min_ttl = Some(instant);

        assert_ne!(s1, s2, "unequal min ttls");
        assert_ne!(s2, s1, "unequal min ttls");

        s2.min_ttl = Some(instant);

        assert_eq!(
            s1, s2,
            "equal subnet_id and min_ttl within DURATION_DIFFERENCE should be equal"
        );

        s2.min_ttl = Some(instant + DURATION_DIFFERENCE);
        assert_ne!(
            s1, s2,
            "equal subnet_id and min_ttl not within DURATION_DIFFERENCE should be unequal"
        );
    }
}
