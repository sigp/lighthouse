pub use prometheus::Error;
use prometheus::{Histogram, HistogramTimer, IntCounter, Result};

pub fn start_timer(histogram: &Result<Histogram>) -> Option<HistogramTimer> {
    if let Ok(histogram) = histogram {
        Some(histogram.start_timer())
    } else {
        None
    }
}

pub fn stop_timer(timer: Option<HistogramTimer>) {
    timer.map(|t| t.observe_duration());
}

pub fn inc_counter(counter: &Result<IntCounter>) {
    if let Ok(counter) = counter {
        counter.inc();
    }
}

pub fn observe(histogram: &Result<Histogram>, value: f64) {
    if let Ok(histogram) = histogram {
        histogram.observe(value);
    }
}

lazy_static! {
    /*
     * Block Processing
     */
    pub static ref BLOCK_PROCESSING_DB_READ: Result<Histogram> = register_histogram!(
        "block_processing_db_read_times",
        "Time spent loading block and state from DB"
    );
    pub static ref BLOCK_PROCESSING_REQUESTS: Result<IntCounter> = register_int_counter!(
        "block_processing_requests",
        "Count of blocks sumbitted for processing"
    );
    pub static ref BLOCK_PROCESSING_SUCCESSES: Result<IntCounter> = register_int_counter!(
        "block_processing_successes",
        "Count of blocks processed without error"
    );
    pub static ref BLOCK_PROCESSING_TIMES: Result<Histogram> =
        register_histogram!("block_processing_times", "Full runtime of block processing");

    /*
     * Block Production
     */
    pub static ref BLOCK_PRODUCTION_REQUESTS: Result<IntCounter> = register_int_counter!(
        "block_production_requests",
        "Count of all block production requests"
    );
    pub static ref BLOCK_PRODUCTION_SUCCESSES: Result<IntCounter> = register_int_counter!(
        "block_production_successes",
        "Count of blocks sucessfully produced."
    );
    pub static ref BLOCK_PRODUCTION_TIMES: Result<Histogram> =
        register_histogram!("block_production_times", "Full runtime of block production");

    /*
     * Block Statistics
     */
    pub static ref OPERATIONS_PER_BLOCK_ATTESTATION: Result<Histogram> = register_histogram!(
        "operations_per_block_attestation",
        "Number of attestations in a block"
    );

    /*
     * Attestation Processing
     */
    pub static ref ATTESTATION_PROCESSING_REQUESTS: Result<IntCounter> = register_int_counter!(
        "attestation_processing_requests",
        "Count of all attestations submitted for processing"
    );
    pub static ref ATTESTATION_PROCESSING_SUCCESSES: Result<IntCounter> = register_int_counter!(
        "attestation_processing_successes",
        "total_attestation_processing_successes"
    );
    pub static ref ATTESTATION_PROCESSING_TIMES: Result<Histogram> = register_histogram!(
        "attestation_processing_times",
        "Full runtime of attestation processing"
    );

    /*
     * Attestation Production
     */
    pub static ref ATTESTATION_PRODUCTION_REQUESTS: Result<IntCounter> = register_int_counter!(
        "attestation_production_requests",
        "Count of all attestation production requests"
    );
    pub static ref ATTESTATION_PRODUCTION_SUCCESSES: Result<IntCounter> = register_int_counter!(
        "attestation_production_successes",
        "Count of attestations processed without error"
    );
    pub static ref ATTESTATION_PRODUCTION_TIMES: Result<Histogram> = register_histogram!(
        "attestation_production_times",
        "Full runtime of attestation production"
    );

    /*
     * Fork Choice
     */
    pub static ref FORK_CHOICE_REQUESTS: Result<IntCounter> = register_int_counter!(
        "fork_choice_requests",
        "Count of occasions where fork choice has tried to find a head"
    );
    pub static ref FORK_CHOICE_CHANGED_HEAD: Result<IntCounter> = register_int_counter!(
        "fork_choice_changed_head",
        "Count of occasions fork choice has found a new head"
    );
    pub static ref FORK_CHOICE_REORG_COUNT: Result<IntCounter> = register_int_counter!(
        "fork_choice_reorg_count",
        "Count of occasions fork choice has switched to a different chain"
    );
    pub static ref FORK_CHOICE_TIMES: Result<Histogram> =
        register_histogram!("fork_choice_time", "Full runtime of fork choice");
}
