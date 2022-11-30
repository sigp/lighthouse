use beacon_chain::{metrics, BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::ValidatorStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use warp_utils::reject::beacon_chain_error;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorCountResponse {
    pub active_ongoing: u64,
    pub active_exiting: u64,
    pub active_slashed: u64,
    pub pending_initialized: u64,
    pub pending_queued: u64,
    pub withdrawal_possible: u64,
    pub withdrawal_done: u64,
    pub exited_unslashed: u64,
    pub exited_slashed: u64,
}

pub fn get_validator_count<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
) -> Result<ValidatorCountResponse, warp::Rejection> {
    let spec = &chain.spec;
    let mut active_ongoing = 0;
    let mut active_exiting = 0;
    let mut active_slashed = 0;
    let mut pending_initialized = 0;
    let mut pending_queued = 0;
    let mut withdrawal_possible = 0;
    let mut withdrawal_done = 0;
    let mut exited_unslashed = 0;
    let mut exited_slashed = 0;

    chain
        .with_head(|head| {
            let state = &head.beacon_state;
            let epoch = state.current_epoch();
            for validator in state.validators() {
                let status =
                    ValidatorStatus::from_validator(validator, epoch, spec.far_future_epoch);

                match status {
                    ValidatorStatus::ActiveOngoing => active_ongoing += 1,
                    ValidatorStatus::ActiveExiting => active_exiting += 1,
                    ValidatorStatus::ActiveSlashed => active_slashed += 1,
                    ValidatorStatus::PendingInitialized => pending_initialized += 1,
                    ValidatorStatus::PendingQueued => pending_queued += 1,
                    ValidatorStatus::WithdrawalPossible => withdrawal_possible += 1,
                    ValidatorStatus::WithdrawalDone => withdrawal_done += 1,
                    ValidatorStatus::ExitedUnslashed => exited_unslashed += 1,
                    ValidatorStatus::ExitedSlashed => exited_slashed += 1,
                    // Since we are not invoking `superset`, all other variants will be 0.
                    _ => (),
                }
            }
            Ok::<(), BeaconChainError>(())
        })
        .map_err(beacon_chain_error)?;

    Ok(ValidatorCountResponse {
        active_ongoing,
        active_exiting,
        active_slashed,
        pending_initialized,
        pending_queued,
        withdrawal_possible,
        withdrawal_done,
        exited_unslashed,
        exited_slashed,
    })
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    attestation_hits: u64,
    attestation_misses: u64,
    head_hit_percentage: f64,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ValidatorMetricsResponse {
    validators: HashMap<String, ValidatorMetrics>,
}

pub fn get_validator_monitor_metrics<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
) -> Result<ValidatorMetricsResponse, warp::Rejection> {
    let ids = chain
        .validator_monitor
        .read()
        .get_all_monitored_validators();
    let mut validators = HashMap::new();

    for id in ids {
        let hits = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_ATTESTER_HIT,
            &[&id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let misses = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_ATTESTER_MISS,
            &[&id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let attestations = hits + misses;
        let head_hit_percentage: f64 = if attestations == 0 {
            0.0
        } else {
            (100 * hits / attestations) as f64
        };

        let metrics = ValidatorMetrics {
            attestation_hits: hits,
            attestation_misses: misses,
            head_hit_percentage,
        };
        validators.insert(id, metrics);
    }

    Ok(ValidatorMetricsResponse { validators })
}
