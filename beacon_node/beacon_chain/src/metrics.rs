pub use prometheus::Error;
use prometheus::{Histogram, IntCounter};

lazy_static! {
    /*
     * Block Processing
     */
    pub static ref BLOCK_PROCESSING_DB_READ: Histogram = register_histogram!(
        "block_processing_db_read_times",
        "Time spent loading block and state from DB"
    )
    .unwrap();
    pub static ref BLOCK_PROCESSING_REQUESTS: IntCounter = register_int_counter!(
        "block_processing_requests",
        "Count of blocks sumbitted for processing"
    )
    .unwrap();
    pub static ref BLOCK_PROCESSING_SUCCESSES: IntCounter = register_int_counter!(
        "block_processing_successes",
        "Count of blocks processed without error"
    )
    .unwrap();
    pub static ref BLOCK_PROCESSING_TIMES: Histogram =
        register_histogram!("block_processing_times", "Full runtime of block processing")
            .unwrap();

    /*
     * Block Production
     */
    pub static ref BLOCK_PRODUCTION_REQUESTS: IntCounter = register_int_counter!(
        "block_production_requests",
        "Count of all block production requests"
    )
    .unwrap();
    pub static ref BLOCK_PRODUCTION_SUCCESSES: IntCounter = register_int_counter!(
        "block_production_successes",
        "Count of blocks sucessfully produced."
    )
    .unwrap();
    pub static ref BLOCK_PRODUCTION_TIMES: Histogram =
        register_histogram!("block_production_times", "Full runtime of block production").unwrap();

    /*
     * Block Statistics
     */
    pub static ref OPERATIONS_PER_BLOCK_ATTESTATION: Histogram = register_histogram!(
        "operations_per_block_attestation",
        "Number of attestations in a block"
    )
    .unwrap();

    /*
     * Attestation Processing
     */
    pub static ref ATTESTATION_PROCESSING_REQUESTS: IntCounter = register_int_counter!(
        "attestation_processing_requests",
        "Count of all attestations submitted for processing"
    )
    .unwrap();
    pub static ref ATTESTATION_PROCESSING_SUCCESSES: IntCounter = register_int_counter!(
        "attestation_processing_successes",
        "total_attestation_processing_successes"
    )
    .unwrap();
    pub static ref ATTESTATION_PROCESSING_TIMES: Histogram = register_histogram!(
        "attestation_processing_times",
        "Full runtime of attestation processing"
    )
    .unwrap();

    /*
     * Attestation Production
     */
    pub static ref ATTESTATION_PRODUCTION_REQUESTS: IntCounter = register_int_counter!(
        "attestation_production_requests",
        "Count of all attestation production requests"
    )
    .unwrap();
    pub static ref ATTESTATION_PRODUCTION_SUCCESSES: IntCounter = register_int_counter!(
        "attestation_production_successes",
        "Count of attestations processed without error"
    )
    .unwrap();
    pub static ref ATTESTATION_PRODUCTION_TIMES: Histogram = register_histogram!(
        "attestation_production_times",
        "Full runtime of attestation production"
    ).unwrap();

    /*
     * Fork Choice
     */
    pub static ref FORK_CHOICE_REQUESTS: IntCounter = register_int_counter!(
        "fork_choice_requests",
        "Count of occasions where fork choice has tried to find a head"
    )
    .unwrap();
    pub static ref FORK_CHOICE_CHANGED_HEAD: IntCounter = register_int_counter!(
        "fork_choice_changed_head",
        "Count of occasions fork choice has found a new head"
    )
    .unwrap();
    pub static ref FORK_CHOICE_REORG_COUNT: IntCounter = register_int_counter!(
        "fork_choice_reorg_count",
        "Count of occasions fork choice has switched to a different chain"
    )
    .unwrap();
    pub static ref FORK_CHOICE_TIMES: Histogram =
        register_histogram!("fork_choice_time", "Full runtime of fork choice").unwrap();
}

pub fn gather_metrics() -> Vec<prometheus::proto::MetricFamily> {
    prometheus::gather()
}
