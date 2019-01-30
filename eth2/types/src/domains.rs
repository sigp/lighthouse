/// Module for the notion of `domain` used to disambiguate BLS signatures across the codebase.
use super::fork::Fork;

/// Get the domain number that represents the fork version and signature domain.
pub fn get_domain(fork: Fork, epoch: u64, domain_type: u64) -> u64 {
    let fork_version = fork.get_version_for(epoch);
    fork_version * 2.pow(32) + domain_type
}
