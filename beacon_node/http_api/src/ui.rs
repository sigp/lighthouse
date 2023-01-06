use beacon_chain::{metrics, BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::ValidatorStatus;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
pub struct ValidatorMetricsRequestData {
    indices: Vec<u64>,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    attestation_hits: u64,
    attestation_misses: u64,
    attestation_hit_percentage: f64,
    attestation_head_hits: u64,
    attestation_head_misses: u64,
    attestation_head_hit_percentage: f64,
    attestation_target_hits: u64,
    attestation_target_misses: u64,
    attestation_target_hit_percentage: f64,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ValidatorMetricsResponse {
    validators: HashMap<String, ValidatorMetrics>,
}

pub fn post_validator_monitor_metrics<T: BeaconChainTypes>(
    request_data: ValidatorMetricsRequestData,
    chain: Arc<BeaconChain<T>>,
) -> Result<ValidatorMetricsResponse, warp::Rejection> {
    let validator_ids = chain
        .validator_monitor
        .read()
        .get_all_monitored_validators()
        .iter()
        .cloned()
        .collect::<HashSet<String>>();

    let indices = request_data
        .indices
        .iter()
        .map(|index| index.to_string())
        .collect::<HashSet<String>>();

    let ids = validator_ids
        .intersection(&indices)
        .collect::<HashSet<&String>>();

    let mut validators = HashMap::new();

    for id in ids {
        let attestation_hits = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_ATTESTER_HIT,
            &[id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let attestation_misses = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_ATTESTER_MISS,
            &[id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let attestations = attestation_hits + attestation_misses;
        let attestation_hit_percentage: f64 = if attestations == 0 {
            0.0
        } else {
            (100 * attestation_hits / attestations) as f64
        };

        let attestation_head_hits = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_HEAD_ATTESTER_HIT,
            &[id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let attestation_head_misses = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_HEAD_ATTESTER_MISS,
            &[id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let head_attestations = attestation_head_hits + attestation_head_misses;
        let attestation_head_hit_percentage: f64 = if head_attestations == 0 {
            0.0
        } else {
            (100 * attestation_head_hits / head_attestations) as f64
        };

        let attestation_target_hits = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_TARGET_ATTESTER_HIT,
            &[id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let attestation_target_misses = metrics::get_int_counter(
            &metrics::VALIDATOR_MONITOR_PREV_EPOCH_ON_CHAIN_TARGET_ATTESTER_MISS,
            &[id],
        )
        .map(|counter| counter.get())
        .unwrap_or(0);
        let target_attestations = attestation_target_hits + attestation_target_misses;
        let attestation_target_hit_percentage: f64 = if target_attestations == 0 {
            0.0
        } else {
            (100 * attestation_target_hits / target_attestations) as f64
        };

        let metrics = ValidatorMetrics {
            attestation_hits,
            attestation_misses,
            attestation_hit_percentage,
            attestation_head_hits,
            attestation_head_misses,
            attestation_head_hit_percentage,
            attestation_target_hits,
            attestation_target_misses,
            attestation_target_hit_percentage,
        };

        validators.insert(id.clone(), metrics);
    }

    Ok(ValidatorMetricsResponse { validators })
}
