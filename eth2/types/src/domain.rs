/// Module for the notion of `domain` used to disambiguate BLS signatures across the codebase.
use super::fork::Fork;

/// Get the domain number that represents the fork version and signature domain.
pub fn get_domain(fork: &Fork, epoch: u64, domain_type: u64) -> u64 {
    let fork_version = fork.get_version_for(epoch);
    fork_version << 32 as u64 + domain_type
}

mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    fn test_get_domain() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let fork = Fork::random_for_test(&mut rng);

        let domain_type = 22;

        let previous = fork.previous_version;
        let current = fork.current_version;
        let epoch = fork.epoch;

        let previous_domain = get_domain(&fork, epoch - 1, domain_type);
        assert_eq!(previous << 32 as u64 + domain_type, previous_domain);
        let current_domain = get_domain(&fork, epoch, domain_type);
        assert_eq!(current << 32 + domain_type, current_domain);
        let current_domain = get_domain(&fork, epoch + 1, domain_type);
        assert_eq!(current << 32 + domain_type, current_domain);
    }
}
