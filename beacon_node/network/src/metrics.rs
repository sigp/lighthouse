pub use lighthouse_metrics::*;

lazy_static! {
    /*
     * Gossip Rx
     */
    pub static ref GOSSIP_BLOCKS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_blocks_rx_total",
        "Count of gossip blocks received"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_unaggregated_attestations_rx_total",
        "Count of gossip unaggregated attestations received"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_aggregated_attestations_rx_total",
        "Count of gossip aggregated attestations received"
    );

    /*
     * Gossip Tx
     */
    pub static ref GOSSIP_BLOCKS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_blocks_tx_total",
        "Count of gossip blocks transmitted"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_unaggregated_attestations_tx_total",
        "Count of gossip unaggregated attestations transmitted"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_aggregated_attestations_tx_total",
        "Count of gossip aggregated attestations transmitted"
    );

    /*
     * Attestation subnet subscriptions
     */
    pub static ref SUBNET_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "network_subnet_subscriptions_total",
        "Count of validator subscription requests."
    );
    pub static ref SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "network_subnet_subscriptions_aggregator_total",
        "Count of validator subscription requests where the subscriber is an aggregator."
    );

    /*
     * Gossip processor
     */
    pub static ref GOSSIP_PROCESSOR_WORKERS_SPAWNED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "gossip_processor_workers_spawned_total",
        "The number of workers ever spawned by the gossip processing pool."
    );
    pub static ref GOSSIP_PROCESSOR_WORKERS_ACTIVE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "gossip_processor_workers_active_total",
        "Count of active workers in the gossip processing pool."
    );
    pub static ref GOSSIP_PROCESSOR_WORK_EVENTS_TOTAL: Result<IntCounter> = try_create_int_counter(
        "gossip_processor_work_events_total",
        "Count of work events processed by the gossip processor manager."
    );
    pub static ref GOSSIP_PROCESSOR_IDLE_EVENTS_TOTAL: Result<IntCounter> = try_create_int_counter(
        "gossip_processor_idle_events_total",
        "Count of idle events processed by the gossip processor manager."
    );
    pub static ref GOSSIP_PROCESSOR_EVENT_HANDLING_SECONDS: Result<Histogram> = try_create_histogram(
        "gossip_processor_event_handling_seconds",
        "Time spend handling a new message and allocating it to a queue or worker."
    );
    pub static ref GOSSIP_PROCESSOR_WORKER_TIME: Result<Histogram> = try_create_histogram(
        "gossip_processor_worker_time",
        "Time taken for a worker to fully process some parcel of work."
    );
    pub static ref GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "gossip_processor_unaggregated_attestation_queue_total",
        "Count of unagg. attestations waiting to be processed."
    );
    pub static ref GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_WORKER_TIME: Result<Histogram> = try_create_histogram(
        "gossip_processor_unaggregated_attestation_worker_time",
        "Time taken for a worker to fully process an unaggregated attestation."
    );
    pub static ref GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "gossip_processor_unaggregated_attestation_verified_total",
        "Total number of unaggregated attestations verified for gossip."
    );
    pub static ref GOSSIP_PROCESSOR_UNAGGREGATED_ATTESTATION_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "gossip_processor_unaggregated_attestation_imported_total",
        "Total number of unaggregated attestations imported to fork choice, etc."
    );
    pub static ref GOSSIP_PROCESSOR_AGGREGATED_ATTESTATION_QUEUE_TOTAL: Result<IntGauge> = try_create_int_gauge(
        "gossip_processor_aggregated_attestation_queue_total",
        "Count of agg. attestations waiting to be processed."
    );
    pub static ref GOSSIP_PROCESSOR_AGGREGATED_ATTESTATION_WORKER_TIME: Result<Histogram> = try_create_histogram(
        "gossip_processor_aggregated_attestation_worker_time",
        "Time taken for a worker to fully process an aggregated attestation."
    );
    pub static ref GOSSIP_PROCESSOR_AGGREGATED_ATTESTATION_VERIFIED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "gossip_processor_aggregated_attestation_verified_total",
        "Total number of aggregated attestations verified for gossip."
    );
    pub static ref GOSSIP_PROCESSOR_AGGREGATED_ATTESTATION_IMPORTED_TOTAL: Result<IntCounter> = try_create_int_counter(
        "gossip_processor_aggregated_attestation_imported_total",
        "Total number of aggregated attestations imported to fork choice, etc."
    );
}
