use super::Context;
use bls::PublicKey;
use eth2::types::{StateId, ValidatorId};
use eth2::BeaconNodeHttpClient;
use parking_lot::RwLock;
use slog::{error, info};
use slot_clock::SlotClock;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{Epoch, EthSpec, PublicKeyBytes};

pub const SUCCESS: &str = "success";
pub const SLASHABLE: &str = "slashable";
pub const SAME_DATA: &str = "same_data";
pub const UNREGISTERED: &str = "unregistered";
pub const FULL_UPDATE: &str = "full_update";
pub const BEACON_BLOCK: &str = "beacon_block";
pub const ATTESTATIONS: &str = "attestations";
pub const AGGREGATES: &str = "aggregates";
pub const CURRENT_EPOCH: &str = "current_epoch";
pub const NEXT_EPOCH: &str = "next_epoch";

pub use lighthouse_metrics::*;

pub struct BalanceMetrics {
    pub index: u64,
    pub balance: u64,
    pub public_key: String,
}
pub struct EpochBalances {
    pub last_epoch: Epoch,
    pub metrics: Vec<BalanceMetrics>,
}

lazy_static::lazy_static! {
    pub static ref GENESIS_DISTANCE: Result<IntGauge> = try_create_int_gauge(
        "vc_genesis_distance_seconds",
        "Distance between now and genesis time"
    );
    pub static ref ENABLED_VALIDATORS_COUNT: Result<IntGauge> = try_create_int_gauge(
        "vc_validators_enabled_count",
        "Number of enabled validators"
    );
    pub static ref TOTAL_VALIDATORS_COUNT: Result<IntGauge> = try_create_int_gauge(
        "vc_validators_total_count",
        "Number of total validators (enabled and disabled)"
    );

    pub static ref SIGNED_BLOCKS_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_beacon_blocks_total",
        "Total count of attempted block signings",
        &["status"]
    );
    pub static ref SIGNED_ATTESTATIONS_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_attestations_total",
        "Total count of attempted Attestation signings",
        &["status"]
    );
    pub static ref SIGNED_AGGREGATES_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_aggregates_total",
        "Total count of attempted SignedAggregateAndProof signings",
        &["status"]
    );
    pub static ref SIGNED_SELECTION_PROOFS_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "vc_signed_selection_proofs_total",
        "Total count of attempted SelectionProof signings",
        &["status"]
    );
    pub static ref DUTIES_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_duties_service_task_times_seconds",
        "Duration to perform duties service tasks",
        &["task"]
    );
    pub static ref FORK_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_fork_service_task_times_seconds",
        "Duration to perform fork service tasks",
        &["task"]
    );
    pub static ref ATTESTATION_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_attestation_service_task_times_seconds",
        "Duration to perform attestation service tasks",
        &["task"]
    );
    pub static ref BLOCK_SERVICE_TIMES: Result<HistogramVec> = try_create_histogram_vec(
        "vc_beacon_block_service_task_times_seconds",
        "Duration to perform beacon block service tasks",
        &["task"]
    );
    pub static ref PROPOSER_COUNT: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "vc_beacon_block_proposer_count",
        "Number of beacon block proposers on this host",
        &["task"]
    );
    pub static ref ATTESTER_COUNT: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "vc_beacon_attester_count",
        "Number of attesters on this host",
        &["task"]
    );
    pub static ref VALIDATOR_BALANCES: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "vc_validator_balances_wei",
        "Validator account balance",
        &["public_key", "index"]
    );
    pub static ref SAVED_BALANCES: RwLock<EpochBalances> = RwLock::new(EpochBalances{
        metrics: Vec::new(),
        last_epoch: Epoch::new(0),
    });
}

pub fn gather_prometheus_metrics<T: EthSpec>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    let mut task_executor = None;
    let mut beacon_cli = None;
    let mut current_epoch = Epoch::new(0);
    let mut pubkeys = Vec::new();

    {
        let shared = ctx.shared.read();

        if let Some(genesis_time) = shared.genesis_time {
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let distance = now.as_secs() as i64 - genesis_time as i64;
                set_gauge(&GENESIS_DISTANCE, distance);
            }
        }

        if let Some(validator_store) = &shared.validator_store {
            let initialized_validators_lock = validator_store.initialized_validators();
            let initialized_validators = initialized_validators_lock.read();

            set_gauge(
                &ENABLED_VALIDATORS_COUNT,
                initialized_validators.num_enabled() as i64,
            );
            set_gauge(
                &TOTAL_VALIDATORS_COUNT,
                initialized_validators.num_total() as i64,
            );

            initialized_validators
                .iter_voting_pubkeys()
                .for_each(|x| pubkeys.push(x.clone()));
            pubkeys.dedup();
        }

        if let Some(duties_service) = &shared.duties_service {
            if let Some(slot) = duties_service.slot_clock.now() {
                current_epoch = slot.epoch(T::slots_per_epoch());
                let next_epoch = current_epoch + 1;

                set_int_gauge(
                    &PROPOSER_COUNT,
                    &[CURRENT_EPOCH],
                    duties_service.proposer_count(current_epoch) as i64,
                );
                set_int_gauge(
                    &ATTESTER_COUNT,
                    &[CURRENT_EPOCH],
                    duties_service.attester_count(current_epoch) as i64,
                );
                set_int_gauge(
                    &ATTESTER_COUNT,
                    &[NEXT_EPOCH],
                    duties_service.attester_count(next_epoch) as i64,
                );
            }
        }

        if let Some(c) = &shared.executor {
            task_executor = Some(c.clone());
        }

        if let Some(c) = &shared.beacon_node {
            beacon_cli = Some(c.clone());
        }
    }

    // We update validator balances if:
    // 1. We received API request to report metrics
    // 2. Validator balances not yet calculated on current epoch
    let mut need_update = false;
    {
        let saved = SAVED_BALANCES.read();
        saved.metrics.iter().for_each(|x| {
            let result = set_int_gauge(
                &VALIDATOR_BALANCES,
                &[&x.public_key, &x.index.to_string()],
                x.balance as i64,
            );

            info!(ctx.log,
            "Read data";
            "pubkey" => &x.public_key,
            "Epoch" => saved.last_epoch,
            "index" => x.index,
            "balance" => x.balance,
            "result" => result
            );
        });
        if saved.last_epoch < current_epoch {
            need_update = true;
        }
    }

    // If need update, we still return the previous balances to avoid blocking Prometheus API call.
    // Spawn an async task to load the new balances. Prometheus will pick them up in next cycle.
    if need_update {
        if let Some(executor) = task_executor {
            if let Some(cli) = beacon_cli {
                let thread_log = ctx.log.clone();
                executor.spawn(
                    async move {
                        // Update epoch first - so if prometheus calls us again before we finish querying beacon node,
                        // we will not enter this logic twice
                        SAVED_BALANCES.write().last_epoch = current_epoch;

                        let mut futures = Vec::new();
                        for x in pubkeys {
                            futures.push(get_validator_balances_by_public_key(x, cli.clone()));
                        }

                        let mut results = Vec::new();
                        for f in futures {
                            match f.await {
                                Ok(c) => results.push(c),
                                Err(e) => error!(
                                thread_log,
                                "Cannot get validator balance";
                                "error" => e
                                ),
                            }
                        }

                        SAVED_BALANCES.write().metrics.clear();
                        SAVED_BALANCES.write().metrics.append(&mut results);
                    },
                    "validator_balances",
                );
            }
        }
    }

    warp_utils::metrics::scrape_health_metrics();

    encoder
        .encode(&lighthouse_metrics::gather(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}

// Beacon API allows querying multiple public keys altogether, but not so we desire, we
// want to know which balance is for which public key, so query one by one
async fn get_validator_balances_by_public_key(
    pubkey: PublicKey,
    beacon_node: BeaconNodeHttpClient,
) -> std::result::Result<BalanceMetrics, String> {
    let validator_id = ValidatorId::PublicKey(PublicKeyBytes::from(&pubkey));
    let ids = vec![validator_id];
    let validator_data = beacon_node
        .get_beacon_states_validator_balances(StateId::Finalized, Some(ids.as_slice()))
        .await
        .map_err(|e| format!("Failed to encode prometheus info: {:?}", e))?
        .map(|result| result.data);

    match validator_data {
        Some(data) => {
            if !data.is_empty() {
                let v = &data[0];
                let metrics = BalanceMetrics {
                    index: v.index,
                    public_key: pubkey.to_string(),
                    balance: v.balance,
                };

                Ok(metrics)
            } else {
                Err(String::from(
                    "No data returned from validator balance query",
                ))
            }
        }

        None => Err(String::from(
            "No data returned from validator balance query",
        )),
    }
}
