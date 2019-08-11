pub use lighthouse_metrics::*;

lazy_static! {
    /*
     * Block Processing
     */
    pub static ref BLOCK_PROCESSING_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "block_processing_requests",
        "Count of blocks submitted for processing"
    );
    pub static ref BLOCK_PROCESSING_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "block_processing_successes",
        "Count of blocks processed without error"
    );
    pub static ref BLOCK_PROCESSING_TIMES: Result<Histogram> =
        try_create_histogram("block_processing_times", "Full runtime of block processing");
    pub static ref BLOCK_PROCESSING_DB_READ: Result<Histogram> = try_create_histogram(
        "block_processing_db_read_times",
        "Time spent loading block and state from DB for block processing"
    );
    pub static ref BLOCK_PROCESSING_CATCHUP_STATE: Result<Histogram> = try_create_histogram(
        "block_processing_catch_up_state_times",
        "Time spent skipping slots on a state before processing a block."
    );
    pub static ref BLOCK_PROCESSING_COMMITTEE: Result<Histogram> = try_create_histogram(
        "block_processing_committee_building_times",
        "Time spent building/obtaining committees for block processing."
    );
    pub static ref BLOCK_PROCESSING_CORE: Result<Histogram> = try_create_histogram(
        "block_processing_core_times",
        "Time spent doing the core per_block_processing state processing."
    );
    pub static ref BLOCK_PROCESSING_STATE_ROOT: Result<Histogram> = try_create_histogram(
        "block_processing_state_root_times",
        "Time spent calculating the state root when processing a block."
    );
    pub static ref BLOCK_PROCESSING_DB_WRITE: Result<Histogram> = try_create_histogram(
        "block_processing_db_write_times",
        "Time spent writing a newly processed block and state to DB"
    );
    pub static ref BLOCK_PROCESSING_FORK_CHOICE_REGISTER: Result<Histogram> = try_create_histogram(
        "block_processing_fork_choice_register_times",
        "Time spent registering the new block with fork choice (but not finding head)"
    );
    pub static ref BLOCK_PROCESSING_FORK_CHOICE_FIND_HEAD: Result<Histogram> = try_create_histogram(
        "block_processing_fork_choice_find_head_times",
        "Time spent finding the new head after processing a new block"
    );

    /*
     * Block Production
     */
    pub static ref BLOCK_PRODUCTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "block_production_requests",
        "Count of all block production requests"
    );
    pub static ref BLOCK_PRODUCTION_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "block_production_successes",
        "Count of blocks successfully produced."
    );
    pub static ref BLOCK_PRODUCTION_TIMES: Result<Histogram> =
        try_create_histogram("block_production_times", "Full runtime of block production");

    /*
     * Block Statistics
     */
    pub static ref OPERATIONS_PER_BLOCK_ATTESTATION: Result<Histogram> = try_create_histogram(
        "operations_per_block_attestation",
        "Number of attestations in a block"
    );

    /*
     * Attestation Processing
     */
    pub static ref ATTESTATION_PROCESSING_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "attestation_processing_requests",
        "Count of all attestations submitted for processing"
    );
    pub static ref ATTESTATION_PROCESSING_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "attestation_processing_successes",
        "total_attestation_processing_successes"
    );
    pub static ref ATTESTATION_PROCESSING_TIMES: Result<Histogram> = try_create_histogram(
        "attestation_processing_times",
        "Full runtime of attestation processing"
    );

    /*
     * Attestation Production
     */
    pub static ref ATTESTATION_PRODUCTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "attestation_production_requests",
        "Count of all attestation production requests"
    );
    pub static ref ATTESTATION_PRODUCTION_SUCCESSES: Result<IntCounter> = try_create_int_counter(
        "attestation_production_successes",
        "Count of attestations processed without error"
    );
    pub static ref ATTESTATION_PRODUCTION_TIMES: Result<Histogram> = try_create_histogram(
        "attestation_production_times",
        "Full runtime of attestation production"
    );

    /*
     * Fork Choice
     */
    pub static ref FORK_CHOICE_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "fork_choice_requests",
        "Count of occasions where fork choice has tried to find a head"
    );
    pub static ref FORK_CHOICE_CHANGED_HEAD: Result<IntCounter> = try_create_int_counter(
        "fork_choice_changed_head",
        "Count of occasions fork choice has found a new head"
    );
    pub static ref FORK_CHOICE_REORG_COUNT: Result<IntCounter> = try_create_int_counter(
        "fork_choice_reorg_count",
        "Count of occasions fork choice has switched to a different chain"
    );
    pub static ref FORK_CHOICE_TIMES: Result<Histogram> =
        try_create_histogram("fork_choice_time", "Full runtime of fork choice");
}
