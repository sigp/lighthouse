use crate::{BeaconChain, BeaconChainTypes};
pub use lighthouse_metrics::*;
use types::{BeaconState, Epoch, Hash256, Slot};

lazy_static! {
    /*
     * Block Processing
     */
    pub static ref BLOCK_PROCESSING_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "beacon_block_processing_requests_total",
        "Count of blocks submitted for processing"
    );
    pub static ref BLOCK_PROCESSING_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "beacon_block_processing_successes_total",
        "Count of blocks processed without error"
    );
    pub static ref BLOCK_PROCESSING_TIMES: Result<Histogram> =
        try_create_histogram("beacon_block_processing_seconds", "Full runtime of block processing");
    pub static ref BLOCK_PROCESSING_BLOCK_ROOT: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_block_root_seconds",
        "Time spent calculating the block root when processing a block."
    );
    pub static ref BLOCK_PROCESSING_DB_READ: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_db_read_seconds",
        "Time spent loading block and state from DB for block processing"
    );
    pub static ref BLOCK_PROCESSING_CATCHUP_STATE: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_catch_up_state_seconds",
        "Time spent skipping slots on a state before processing a block."
    );
    pub static ref BLOCK_PROCESSING_COMMITTEE: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_committee_building_seconds",
        "Time spent building/obtaining committees for block processing."
    );
    pub static ref BLOCK_PROCESSING_CORE: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_core_seconds",
        "Time spent doing the core per_block_processing state processing."
    );
    pub static ref BLOCK_PROCESSING_STATE_ROOT: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_state_root_seconds",
        "Time spent calculating the state root when processing a block."
    );
    pub static ref BLOCK_PROCESSING_DB_WRITE: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_db_write_seconds",
        "Time spent writing a newly processed block and state to DB"
    );
    pub static ref BLOCK_PROCESSING_FORK_CHOICE_REGISTER: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_fork_choice_register_seconds",
        "Time spent registering the new block with fork choice (but not finding head)"
    );
    pub static ref BLOCK_PROCESSING_FORK_CHOICE_FIND_HEAD: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_fork_choice_find_head_seconds",
        "Time spent finding the new head after processing a new block"
    );

    /*
     * Block Production
     */
    pub static ref BLOCK_PRODUCTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "beacon_block_production_requests_total",
        "Count of all block production requests"
    );
    pub static ref BLOCK_PRODUCTION_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "beacon_block_production_successes_total",
        "Count of blocks successfully produced."
    );
    pub static ref BLOCK_PRODUCTION_TIMES: Result<Histogram> =
        try_create_histogram("beacon_block_production_seconds", "Full runtime of block production");

    /*
     * Block Statistics
     */
    pub static ref OPERATIONS_PER_BLOCK_ATTESTATION: Result<Histogram> = try_create_histogram(
        "beacon_operations_per_block_attestation_total",
        "Number of attestations in a block"
    );

    /*
     * Attestation Processing
     */
    pub static ref ATTESTATION_PROCESSING_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "beacon_attestation_processing_requests_total",
        "Count of all attestations submitted for processing"
    );
    pub static ref ATTESTATION_PROCESSING_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "beacon_attestation_processing_successes_total",
        "total_attestation_processing_successes"
    );
    pub static ref ATTESTATION_PROCESSING_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_seconds",
        "Full runtime of attestation processing"
    );
    pub static ref ATTESTATION_PROCESSING_CORE: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_core_seconds",
        "Time spent on the core spec processing of attestation processing"
    );

    /*
     * Attestation Production
     */
    pub static ref ATTESTATION_PRODUCTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "beacon_attestation_production_requests_total",
        "Count of all attestation production requests"
    );
    pub static ref ATTESTATION_PRODUCTION_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "beacon_attestation_production_successes_total",
        "Count of attestations processed without error"
    );
    pub static ref ATTESTATION_PRODUCTION_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_production_seconds",
        "Full runtime of attestation production"
    );

    /*
     * Fork Choice
     */
    pub static ref FORK_CHOICE_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "beacon_fork_choice_requests_total",
        "Count of occasions where fork choice has tried to find a head"
    );
    pub static ref FORK_CHOICE_ERRORS: Result<IntCounter> = try_create_int_counter(
        "beacon_fork_choice_errors_total",
        "Count of occasions where fork choice has returned an error when trying to find a head"
    );
    pub static ref FORK_CHOICE_CHANGED_HEAD: Result<IntCounter> = try_create_int_counter(
        "beacon_fork_choice_changed_head_total",
        "Count of occasions fork choice has found a new head"
    );
    pub static ref FORK_CHOICE_REORG_COUNT: Result<IntCounter> = try_create_int_counter(
        "beacon_fork_choice_reorg_total",
        "Count of occasions fork choice has switched to a different chain"
    );
    pub static ref FORK_CHOICE_TIMES: Result<Histogram> =
        try_create_histogram("beacon_fork_choice_seconds", "Full runtime of fork choice");
    pub static ref FORK_CHOICE_FIND_HEAD_TIMES: Result<Histogram> =
        try_create_histogram("beacon_fork_choice_find_head_seconds", "Full runtime of fork choice find_head function");
    pub static ref FORK_CHOICE_PROCESS_BLOCK_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_fork_choice_process_block_seconds",
        "Time taken to add a block and all attestations to fork choice"
    );
    pub static ref FORK_CHOICE_PROCESS_ATTESTATION_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_fork_choice_process_attestation_seconds",
        "Time taken to add an attestation to fork choice"
    );

    /*
     * Persisting BeaconChain to disk
     */
    pub static ref PERSIST_CHAIN: Result<Histogram> =
        try_create_histogram("beacon_persist_chain", "Time taken to update the canonical head");

    /*
     * Chain Head
     */
    pub static ref UPDATE_HEAD_TIMES: Result<Histogram> =
        try_create_histogram("beacon_update_head_seconds", "Time taken to update the canonical head");
    pub static ref HEAD_STATE_SLOT: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_slot", "Slot of the block at the head of the chain");
    pub static ref HEAD_STATE_ROOT: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_root", "Root of the block at the head of the chain");
    pub static ref HEAD_STATE_LATEST_BLOCK_SLOT: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_latest_block_slot", "Latest block slot at the head of the chain");
    pub static ref HEAD_STATE_CURRENT_JUSTIFIED_ROOT: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_current_justified_root", "Current justified root at the head of the chain");
    pub static ref HEAD_STATE_CURRENT_JUSTIFIED_EPOCH: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_current_justified_epoch", "Current justified epoch at the head of the chain");
    pub static ref HEAD_STATE_PREVIOUS_JUSTIFIED_ROOT: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_previous_justified_root", "Previous justified root at the head of the chain");
    pub static ref HEAD_STATE_PREVIOUS_JUSTIFIED_EPOCH: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_previous_justified_epoch", "Previous justified epoch at the head of the chain");
    pub static ref HEAD_STATE_FINALIZED_ROOT: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_finalized_root", "Finalized root at the head of the chain");
    pub static ref HEAD_STATE_FINALIZED_EPOCH: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_finalized_epoch", "Finalized epoch at the head of the chain");
    pub static ref HEAD_STATE_SHARDS: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_shard_total", "Count of shards in the beacon chain");
    pub static ref HEAD_STATE_TOTAL_VALIDATORS: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_total_validators_total", "Count of validators at the head of the chain");
    pub static ref HEAD_STATE_ACTIVE_VALIDATORS: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_active_validators_total", "Count of active validators at the head of the chain");
    pub static ref HEAD_STATE_VALIDATOR_BALANCES: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_validator_balances_total", "Sum of all validator balances at the head of the chain");
    pub static ref HEAD_STATE_SLASHED_VALIDATORS: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_slashed_validators_total", "Count of all slashed validators at the head of the chain");
    pub static ref HEAD_STATE_WITHDRAWN_VALIDATORS: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_withdrawn_validators_total", "Sum of all validator balances at the head of the chain");
    pub static ref HEAD_STATE_ETH1_DEPOSIT_INDEX: Result<IntGauge> =
        try_create_int_gauge("beacon_head_state_eth1_deposit_index", "Eth1 deposit index at the head of the chain");
}

/// Scrape the `beacon_chain` for metrics that are not constantly updated (e.g., the present slot,
/// head state info, etc) and update the Prometheus `DEFAULT_REGISTRY`.
pub fn scrape_for_metrics<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) {
    scrape_head_state::<T>(
        &beacon_chain.head().beacon_state,
        beacon_chain.head().beacon_state_root,
    );
}

/// Scrape the given `state` assuming it's the head state, updating the `DEFAULT_REGISTRY`.
fn scrape_head_state<T: BeaconChainTypes>(state: &BeaconState<T::EthSpec>, state_root: Hash256) {
    set_gauge_by_slot(&HEAD_STATE_SLOT, state.slot);
    set_gauge_by_hash(&HEAD_STATE_ROOT, state_root);
    set_gauge_by_slot(
        &HEAD_STATE_LATEST_BLOCK_SLOT,
        state.latest_block_header.slot,
    );
    set_gauge_by_hash(
        &HEAD_STATE_CURRENT_JUSTIFIED_ROOT,
        state.current_justified_checkpoint.root,
    );
    set_gauge_by_epoch(
        &HEAD_STATE_CURRENT_JUSTIFIED_EPOCH,
        state.current_justified_checkpoint.epoch,
    );
    set_gauge_by_hash(
        &HEAD_STATE_PREVIOUS_JUSTIFIED_ROOT,
        state.previous_justified_checkpoint.root,
    );
    set_gauge_by_epoch(
        &HEAD_STATE_PREVIOUS_JUSTIFIED_EPOCH,
        state.previous_justified_checkpoint.epoch,
    );
    set_gauge_by_hash(&HEAD_STATE_FINALIZED_ROOT, state.finalized_checkpoint.root);
    set_gauge_by_epoch(
        &HEAD_STATE_FINALIZED_EPOCH,
        state.finalized_checkpoint.epoch,
    );
    set_gauge_by_usize(&HEAD_STATE_SHARDS, state.previous_crosslinks.len());
    set_gauge_by_usize(&HEAD_STATE_TOTAL_VALIDATORS, state.validators.len());
    set_gauge_by_u64(&HEAD_STATE_VALIDATOR_BALANCES, state.balances.iter().sum());
    set_gauge_by_usize(
        &HEAD_STATE_ACTIVE_VALIDATORS,
        state
            .validators
            .iter()
            .filter(|v| v.is_active_at(state.current_epoch()))
            .count(),
    );
    set_gauge_by_usize(
        &HEAD_STATE_SLASHED_VALIDATORS,
        state.validators.iter().filter(|v| v.slashed).count(),
    );
    set_gauge_by_usize(
        &HEAD_STATE_WITHDRAWN_VALIDATORS,
        state
            .validators
            .iter()
            .filter(|v| v.is_withdrawable_at(state.current_epoch()))
            .count(),
    );
    set_gauge_by_u64(&HEAD_STATE_ETH1_DEPOSIT_INDEX, state.eth1_deposit_index);
}

fn set_gauge_by_slot(gauge: &Result<IntGauge>, value: Slot) {
    set_gauge(gauge, value.as_u64() as i64);
}

fn set_gauge_by_epoch(gauge: &Result<IntGauge>, value: Epoch) {
    set_gauge(gauge, value.as_u64() as i64);
}

fn set_gauge_by_hash(gauge: &Result<IntGauge>, value: Hash256) {
    set_gauge(gauge, value.to_low_u64_le() as i64);
}

fn set_gauge_by_usize(gauge: &Result<IntGauge>, value: usize) {
    set_gauge(gauge, value as i64);
}

fn set_gauge_by_u64(gauge: &Result<IntGauge>, value: u64) {
    set_gauge(gauge, value as i64);
}
