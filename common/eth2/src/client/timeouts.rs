//! HTTP client timeout configurations.

use std::time::Duration;

/// A struct to define a variety of different timeouts for different validator tasks to ensure
/// proper fallback behaviour is triggered.
#[derive(Clone, Debug, PartialEq)]
pub struct Timeouts {
    pub attestation: Duration,
    pub attester_duties: Duration,
    pub liveness: Duration,
    pub proposal: Duration,
    pub proposer_duties: Duration,
    pub sync_duties: Duration,
    pub get_beacon_blocks_ssz: Duration,
    pub get_debug_beacon_states: Duration,
    pub get_deposit_snapshot: Duration,
    pub get_validator_block: Duration,
    pub sync_committee_contribution: Duration,
    pub attestation_subscriptions: Duration,
}

impl Timeouts {
    pub fn set_all(timeout: Duration) -> Self {
        Timeouts {
            attestation: timeout,
            attester_duties: timeout,
            liveness: timeout,
            proposal: timeout,
            proposer_duties: timeout,
            sync_duties: timeout,
            get_beacon_blocks_ssz: timeout,
            get_debug_beacon_states: timeout,
            get_deposit_snapshot: timeout,
            get_validator_block: timeout,
            sync_committee_contribution: timeout,
            attestation_subscriptions: timeout,
        }
    }
}