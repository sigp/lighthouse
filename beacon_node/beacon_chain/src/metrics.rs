use crate::{BeaconChain, BeaconChainTypes};
use lazy_static::lazy_static;
pub use lighthouse_metrics::*;
use slot_clock::SlotClock;
use types::{BeaconState, Epoch, EthSpec, Hash256, Slot};

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
    pub static ref BLOCK_PROCESSING_SIGNATURE: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_signature_seconds",
        "Time spent doing signature verification for a block."
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
    pub static ref BLOCK_PROCESSING_ATTESTATION_OBSERVATION: Result<Histogram> = try_create_histogram(
        "beacon_block_processing_attestation_observation_seconds",
        "Time spent hashing and remembering all the attestations in the block"
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
    pub static ref BLOCK_PRODUCTION_STATE_LOAD_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_block_production_state_load_seconds",
        "Time taken to load the base state for block production"
    );
    pub static ref BLOCK_PRODUCTION_SLOT_PROCESS_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_block_production_slot_process_seconds",
        "Time taken to advance the state to the block production slot"
    );
    pub static ref BLOCK_PRODUCTION_UNAGGREGATED_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_block_production_unaggregated_seconds",
        "Time taken to import the naive aggregation pool for block production"
    );
    pub static ref BLOCK_PRODUCTION_ATTESTATION_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_block_production_attestation_seconds",
        "Time taken to pack attestations into a block"
    );
    pub static ref BLOCK_PRODUCTION_PROCESS_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_block_production_process_seconds",
        "Time taken to process the block produced"
    );
    pub static ref BLOCK_PRODUCTION_STATE_ROOT_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_block_production_state_root_seconds",
        "Time taken to calculate the block's state root"
    );

    /*
     * Block Statistics
     */
    pub static ref OPERATIONS_PER_BLOCK_ATTESTATION: Result<Histogram> = try_create_histogram(
        "beacon_operations_per_block_attestation_total",
        "Number of attestations in a block"
    );

    /*
     * Unaggregated Attestation Verification
     */
    pub static ref UNAGGREGATED_ATTESTATION_PROCESSING_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "beacon_unaggregated_attestation_processing_requests_total",
        "Count of all unaggregated attestations submitted for processing"
    );
    pub static ref UNAGGREGATED_ATTESTATION_PROCESSING_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "beacon_unaggregated_attestation_processing_successes_total",
        "Number of unaggregated attestations verified for gossip"
    );
    pub static ref UNAGGREGATED_ATTESTATION_GOSSIP_VERIFICATION_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_unaggregated_attestation_gossip_verification_seconds",
        "Full runtime of aggregated attestation gossip verification"
    );

    /*
     * Aggregated Attestation Verification
     */
    pub static ref AGGREGATED_ATTESTATION_PROCESSING_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "beacon_aggregated_attestation_processing_requests_total",
        "Count of all aggregated attestations submitted for processing"
    );
    pub static ref AGGREGATED_ATTESTATION_PROCESSING_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "beacon_aggregated_attestation_processing_successes_total",
        "Number of aggregated attestations verified for gossip"
    );
    pub static ref AGGREGATED_ATTESTATION_GOSSIP_VERIFICATION_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_aggregated_attestation_gossip_verification_seconds",
        "Full runtime of aggregated attestation gossip verification"
    );

    /*
     * General Attestation Processing
     */
    pub static ref ATTESTATION_PROCESSING_APPLY_TO_AGG_POOL: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_apply_to_agg_pool",
        "Time spent applying an attestation to the naive aggregation pool"
    );
    pub static ref ATTESTATION_PROCESSING_AGG_POOL_MAPS_WRITE_LOCK: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_agg_pool_maps_write_lock",
        "Time spent waiting for the maps write lock when adding to the agg poll"
    );
    pub static ref ATTESTATION_PROCESSING_AGG_POOL_PRUNE: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_agg_pool_prune",
        "Time spent for the agg pool to prune"
    );
    pub static ref ATTESTATION_PROCESSING_AGG_POOL_INSERT: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_agg_pool_insert",
        "Time spent for the outer pool.insert() function of agg pool"
    );
    pub static ref ATTESTATION_PROCESSING_AGG_POOL_CORE_INSERT: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_agg_pool_core_insert",
        "Time spent for the core map.insert() function of agg pool"
    );
    pub static ref ATTESTATION_PROCESSING_AGG_POOL_AGGREGATION: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_agg_pool_aggregation",
        "Time spent doing signature aggregation when adding to the agg poll"
    );
    pub static ref ATTESTATION_PROCESSING_AGG_POOL_CREATE_MAP: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_agg_pool_create_map",
        "Time spent for creating a map for a new slot"
    );
    pub static ref ATTESTATION_PROCESSING_APPLY_TO_OP_POOL: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_apply_to_op_pool",
        "Time spent applying an attestation to the block inclusion pool"
    );

    /*
     * Attestation Processing
     */
    pub static ref ATTESTATION_PROCESSING_SHUFFLING_CACHE_WAIT_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_shuffling_cache_wait_seconds",
        "Time spent on waiting for the shuffling cache lock during attestation processing"
    );
    pub static ref ATTESTATION_PROCESSING_COMMITTEE_BUILDING_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_committee_building_seconds",
        "Time spent on building committees during attestation processing"
    );
    pub static ref ATTESTATION_PROCESSING_STATE_READ_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_state_read_seconds",
        "Time spent on reading the state during attestation processing"
    );
    pub static ref ATTESTATION_PROCESSING_STATE_SKIP_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_state_skip_seconds",
        "Time spent on reading the state during attestation processing"
    );
    pub static ref ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_signature_setup_seconds",
        "Time spent on setting up for the signature verification of attestation processing"
    );
    pub static ref ATTESTATION_PROCESSING_SIGNATURE_TIMES: Result<Histogram> = try_create_histogram(
        "beacon_attestation_processing_signature_seconds",
        "Time spent on the signature verification of attestation processing"
    );

    /*
     * Shuffling cache
     */
    pub static ref SHUFFLING_CACHE_HITS: Result<IntCounter> =
        try_create_int_counter("beacon_shuffling_cache_hits_total", "Count of times shuffling cache fulfils request");
    pub static ref SHUFFLING_CACHE_MISSES: Result<IntCounter> =
        try_create_int_counter("beacon_shuffling_cache_misses_total", "Count of times shuffling cache fulfils request");

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
}

// Second lazy-static block is used to account for macro recursion limit.
lazy_static! {
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
    pub static ref BALANCES_CACHE_HITS: Result<IntCounter> =
        try_create_int_counter("beacon_balances_cache_hits_total", "Count of times balances cache fulfils request");
    pub static ref BALANCES_CACHE_MISSES: Result<IntCounter> =
        try_create_int_counter("beacon_balances_cache_misses_total", "Count of times balances cache fulfils request");

    /*
     * Persisting BeaconChain components to disk
     */
    pub static ref PERSIST_HEAD: Result<Histogram> =
        try_create_histogram("beacon_persist_head", "Time taken to persist the canonical head");
    pub static ref PERSIST_OP_POOL: Result<Histogram> =
        try_create_histogram("beacon_persist_op_pool", "Time taken to persist the operations pool");
    pub static ref PERSIST_ETH1_CACHE: Result<Histogram> =
        try_create_histogram("beacon_persist_eth1_cache", "Time taken to persist the eth1 caches");
    pub static ref PERSIST_FORK_CHOICE: Result<Histogram> =
        try_create_histogram("beacon_persist_fork_choice", "Time taken to persist the fork choice struct");

    /*
     * Eth1
     */
    pub static ref DEFAULT_ETH1_VOTES: Result<IntCounter> =
        try_create_int_counter("beacon_eth1_default_votes", "Count of times we have voted default value for eth1 data");

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

    /*
     * Operation Pool
     */
    pub static ref OP_POOL_NUM_ATTESTATIONS: Result<IntGauge> =
        try_create_int_gauge("beacon_op_pool_attestations_total", "Count of attestations in the op pool");
    pub static ref OP_POOL_NUM_ATTESTER_SLASHINGS: Result<IntGauge> =
        try_create_int_gauge("beacon_op_pool_attester_slashings_total", "Count of attester slashings in the op pool");
    pub static ref OP_POOL_NUM_PROPOSER_SLASHINGS: Result<IntGauge> =
        try_create_int_gauge("beacon_op_pool_proposer_slashings_total", "Count of proposer slashings in the op pool");
    pub static ref OP_POOL_NUM_VOLUNTARY_EXITS: Result<IntGauge> =
        try_create_int_gauge("beacon_op_pool_voluntary_exits_total", "Count of voluntary exits in the op pool");

    /*
     * Participation Metrics
     */
    pub static ref PARTICIPATION_PREV_EPOCH_ATTESTER: Result<Gauge> = try_create_float_gauge(
        "beacon_participation_prev_epoch_attester",
        "Ratio of attesting balances to total balances"
    );
    pub static ref PARTICIPATION_PREV_EPOCH_TARGET_ATTESTER: Result<Gauge> = try_create_float_gauge(
        "beacon_participation_prev_epoch_target_attester",
        "Ratio of target-attesting balances to total balances"
    );
    pub static ref PARTICIPATION_PREV_EPOCH_HEAD_ATTESTER: Result<Gauge> = try_create_float_gauge(
        "beacon_participation_prev_epoch_head_attester",
        "Ratio of head-attesting balances to total balances"
    );

    /*
     * Attestation Observation Metrics
     */
    pub static ref ATTN_OBSERVATION_PREV_EPOCH_ATTESTERS: Result<IntGauge> = try_create_int_gauge(
        "beacon_attn_observation_epoch_attesters",
        "Count of attesters that have been seen by the beacon chain in the previous epoch"
    );
    pub static ref ATTN_OBSERVATION_PREV_EPOCH_AGGREGATORS: Result<IntGauge> = try_create_int_gauge(
        "beacon_attn_observation_epoch_aggregators",
        "Count of aggregators that have been seen by the beacon chain in the previous epoch"
    );
}

// Third lazy-static block is used to account for macro recursion limit.
lazy_static! {
    /*
     * Validator Monitor Metrics (balances, etc)
     */
    pub static ref VALIDATOR_MONITOR_BALANCE_GWEI: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_balance_gwei",
            "The validator's balance in gwei.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_EFFECTIVE_BALANCE_GWEI: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_effective_balance_gwei",
            "The validator's effective balance in gwei.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_SLASHED: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_slashed",
            "Set to 1 if the validator is slashed.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_ACTIVE: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_active",
            "Set to 1 if the validator is active.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_EXITED: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_exited",
            "Set to 1 if the validator is exited.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_WITHDRAWABLE: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_withdrawable",
            "Set to 1 if the validator is withdrawable.",
            &["validator"]
        );
    pub static ref VALIDATOR_ACTIVATION_ELIGIBILITY_EPOCH: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_activation_eligibility_epoch",
            "Set to the epoch where the validator will be eligible for activation.",
            &["validator"]
        );
    pub static ref VALIDATOR_ACTIVATION_EPOCH: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_activation_epoch",
            "Set to the epoch where the validator will activate.",
            &["validator"]
        );
    pub static ref VALIDATOR_EXIT_EPOCH: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_exit_epoch",
            "Set to the epoch where the validator will exit.",
            &["validator"]
        );
    pub static ref VALIDATOR_WITHDRAWABLE_EPOCH: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_withdrawable_epoch",
            "Set to the epoch where the validator will be withdrawable.",
            &["validator"]
        );

    /*
     * Validator Monitor Metrics (per-epoch summaries)
     */
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATIONS_TOTAL: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_attestations_total",
            "The number of unagg. attestations seen in the previous epoch.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATIONS_MIN_DELAY_SECONDS: Result<HistogramVec> =
        try_create_histogram_vec(
            "validator_monitor_prev_epoch_attestations_min_delay_seconds",
            "The min delay between when the validator should send the attestation and when it was received.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATION_AGGREGATE_INCLUSIONS: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_attestation_aggregate_inclusions",
            "The count of times an attestation was seen inside an aggregate.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATION_BLOCK_INCLUSIONS: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_attestation_block_inclusions",
            "The count of times an attestation was seen inside a block.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_ATTESTATION_BLOCK_MIN_INCLUSION_DISTANCE: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_attestation_block_min_inclusion_distance",
            "The minimum inclusion distance observed for the inclusion of an attestation in a block.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_BEACON_BLOCKS_TOTAL: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_beacon_blocks_total",
            "The number of beacon_blocks seen in the previous epoch.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_BEACON_BLOCKS_MIN_DELAY_SECONDS: Result<HistogramVec> =
        try_create_histogram_vec(
            "validator_monitor_prev_epoch_beacon_blocks_min_delay_seconds",
            "The min delay between when the validator should send the block and when it was received.",
            &["validator"]
       );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_AGGREGATES_TOTAL: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_aggregates_total",
            "The number of aggregates seen in the previous epoch.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_AGGREGATES_MIN_DELAY_SECONDS: Result<HistogramVec> =
        try_create_histogram_vec(
            "validator_monitor_prev_epoch_aggregates_min_delay_seconds",
            "The min delay between when the validator should send the aggregate and when it was received.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_EXITS_TOTAL: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_exits_total",
            "The number of exits seen in the previous epoch.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_PROPOSER_SLASHINGS_TOTAL: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_proposer_slashings_total",
            "The number of proposer slashings seen in the previous epoch.",
            &["validator"]
        );
    pub static ref VALIDATOR_MONITOR_PREV_EPOCH_ATTESTER_SLASHINGS_TOTAL: Result<IntGaugeVec> =
        try_create_int_gauge_vec(
            "validator_monitor_prev_epoch_attester_slashings_total",
            "The number of attester slashings seen in the previous epoch.",
            &["validator"]
        );

    /*
     * Validator Monitor Metrics (real-time)
     */
    pub static ref VALIDATOR_MONITOR_VALIDATORS_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "validator_monitor_validators_total",
        "Count of validators that are specifically monitored by this beacon node"
    );
    pub static ref VALIDATOR_MONITOR_UNAGGREGATED_ATTESTATION_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_unaggregated_attestation_total",
        "Number of unaggregated attestations seen",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_UNAGGREGATED_ATTESTATION_DELAY_SECONDS: Result<HistogramVec> = try_create_histogram_vec(
        "validator_monitor_unaggregated_attestation_delay_seconds",
        "The delay between when the validator should send the attestation and when it was received.",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_AGGREGATED_ATTESTATION_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_aggregated_attestation_total",
        "Number of aggregated attestations seen",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_AGGREGATED_ATTESTATION_DELAY_SECONDS: Result<HistogramVec> = try_create_histogram_vec(
        "validator_monitor_aggregated_attestation_delay_seconds",
        "The delay between then the validator should send the aggregate and when it was received.",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_ATTESTATION_IN_AGGREGATE_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_attestation_in_aggregate_total",
        "Number of times an attestation has been seen in an aggregate",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_ATTESTATION_IN_AGGREGATE_DELAY_SECONDS: Result<HistogramVec> = try_create_histogram_vec(
        "validator_monitor_attestation_in_aggregate_delay_seconds",
        "The delay between when the validator should send the aggregate and when it was received.",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_ATTESTATION_IN_BLOCK_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_attestation_in_block_total",
        "Number of times an attestation has been seen in a block",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_ATTESTATION_IN_BLOCK_DELAY_SLOTS: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "validator_monitor_attestation_in_block_delay_slots",
        "The excess slots (beyond the minimum delay) between the attestation slot and the block slot.",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_BEACON_BLOCK_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_beacon_block_total",
        "Number of beacon blocks seen",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_BEACON_BLOCK_DELAY_SECONDS: Result<HistogramVec> = try_create_histogram_vec(
        "validator_monitor_beacon_block_delay_seconds",
        "The delay between when the validator should send the block and when it was received.",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_EXIT_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_exit_total",
        "Number of beacon exits seen",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_PROPOSER_SLASHING_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_proposer_slashing_total",
        "Number of proposer slashings seen",
        &["src", "validator"]
    );
    pub static ref VALIDATOR_MONITOR_ATTESTER_SLASHING_TOTAL: Result<IntCounterVec> = try_create_int_counter_vec(
        "validator_monitor_attester_slashing_total",
        "Number of attester slashings seen",
        &["src", "validator"]
    );

}

/// Scrape the `beacon_chain` for metrics that are not constantly updated (e.g., the present slot,
/// head state info, etc) and update the Prometheus `DEFAULT_REGISTRY`.
pub fn scrape_for_metrics<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) {
    if let Ok(head) = beacon_chain.head() {
        scrape_head_state::<T>(&head.beacon_state, head.beacon_state_root)
    }

    if let Some(slot) = beacon_chain.slot_clock.now() {
        scrape_attestation_observation(slot, beacon_chain);
    }

    set_gauge_by_usize(
        &OP_POOL_NUM_ATTESTATIONS,
        beacon_chain.op_pool.num_attestations(),
    );
    set_gauge_by_usize(
        &OP_POOL_NUM_ATTESTER_SLASHINGS,
        beacon_chain.op_pool.num_attester_slashings(),
    );
    set_gauge_by_usize(
        &OP_POOL_NUM_PROPOSER_SLASHINGS,
        beacon_chain.op_pool.num_proposer_slashings(),
    );
    set_gauge_by_usize(
        &OP_POOL_NUM_VOLUNTARY_EXITS,
        beacon_chain.op_pool.num_voluntary_exits(),
    );

    beacon_chain
        .validator_monitor
        .read()
        .scrape_metrics(&beacon_chain.slot_clock, &beacon_chain.spec);
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

fn scrape_attestation_observation<T: BeaconChainTypes>(slot_now: Slot, chain: &BeaconChain<T>) {
    let prev_epoch = slot_now.epoch(T::EthSpec::slots_per_epoch()) - 1;

    if let Some(count) = chain
        .observed_attesters
        .read()
        .observed_validator_count(prev_epoch)
    {
        set_gauge_by_usize(&ATTN_OBSERVATION_PREV_EPOCH_ATTESTERS, count);
    }

    if let Some(count) = chain
        .observed_aggregators
        .read()
        .observed_validator_count(prev_epoch)
    {
        set_gauge_by_usize(&ATTN_OBSERVATION_PREV_EPOCH_AGGREGATORS, count);
    }
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
