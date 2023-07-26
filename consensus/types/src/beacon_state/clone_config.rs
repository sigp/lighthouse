/// Configuration struct for controlling which caches of a `BeaconState` should be cloned.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct CloneConfig {
    pub committee_caches: bool,
    pub pubkey_cache: bool,
    pub exit_cache: bool,
    pub tree_hash_cache: bool,
    pub progressive_balances_cache: bool,
}

impl CloneConfig {
    pub fn all() -> Self {
        Self {
            committee_caches: true,
            pubkey_cache: true,
            exit_cache: true,
            tree_hash_cache: true,
            progressive_balances_cache: true,
        }
    }

    pub fn none() -> Self {
        Self::default()
    }

    pub fn committee_caches_only() -> Self {
        Self {
            committee_caches: true,
            ..Self::none()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sanity() {
        assert!(CloneConfig::all().pubkey_cache);
        assert!(!CloneConfig::none().tree_hash_cache);
        assert!(CloneConfig::committee_caches_only().committee_caches);
        assert!(!CloneConfig::committee_caches_only().exit_cache);
    }
}
